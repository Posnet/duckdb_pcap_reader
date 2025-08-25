#include "duckdb_extension.h"
#include "pcap_reader.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#include <fcntl.h>
#include <io.h>
#include <errno.h>
#endif

DUCKDB_EXTENSION_EXTERN

// State for the pcap reader
typedef struct {
    FILE *file;
    pcap_file_header_t file_header;
    int needs_swap;  // Whether we need to swap byte order
    int is_nanosecond;  // Whether timestamps are in nanoseconds
    char *filename;
    int is_stdin;  // Whether we're reading from stdin
    uint8_t *packet_buffer;  // Reusable buffer for packet data
    size_t buffer_size;      // Current buffer size
} pcap_reader_state_t;

// Swap byte order for 32-bit values
static uint32_t swap32(uint32_t value) {
    return ((value & 0xFF000000) >> 24) |
           ((value & 0x00FF0000) >> 8) |
           ((value & 0x0000FF00) << 8) |
           ((value & 0x000000FF) << 24);
}

// Destructor for bind data
static void PcapReaderBindDataFree(void *data) {
    pcap_reader_state_t *state = (pcap_reader_state_t *)data;
    if (state) {
        if (state->filename) {
            free(state->filename);
        }
        free(state);
    }
}

// Destructor for init data
static void PcapReaderInitDataFree(void *data) {
    pcap_reader_state_t *state = (pcap_reader_state_t *)data;
    if (state) {
        if (state->file && !state->is_stdin) {
            fclose(state->file);
        }
        if (state->packet_buffer) {
            duckdb_free(state->packet_buffer);
        }
        // Don't free filename here as it's owned by bind data
        free(state);
    }
}

// Bind function for the pcap reader
static void PcapReaderBind(duckdb_bind_info info) {
    // Get the file path parameter
    duckdb_value filename_value = duckdb_bind_get_parameter(info, 0);
    const char *filename = duckdb_get_varchar(filename_value);
    
    if (!filename) {
        duckdb_bind_set_error(info, "Filename parameter is required");
        duckdb_destroy_value(&filename_value);
        return;
    }
    
    // Create state for the reader
    pcap_reader_state_t *state = (pcap_reader_state_t *)duckdb_malloc(sizeof(pcap_reader_state_t));
    if (!state) {
        duckdb_bind_set_error(info, "Failed to allocate memory for pcap reader state");
        duckdb_free((void *)filename);
        duckdb_destroy_value(&filename_value);
        return;
    }
    
    // Store filename - we need to copy it as the value will be destroyed
    size_t filename_len = strlen(filename) + 1;
    state->filename = (char *)duckdb_malloc(filename_len);
    if (!state->filename) {
        duckdb_bind_set_error(info, "Failed to allocate memory for filename");
        duckdb_free(state);
        duckdb_free((void *)filename);
        duckdb_destroy_value(&filename_value);
        return;
    }
#ifdef _WIN32
    strcpy_s(state->filename, filename_len, filename);
#else
    memcpy(state->filename, filename, filename_len);
#endif
    state->file = NULL;
    state->needs_swap = 0;
    state->is_nanosecond = 0;
    state->is_stdin = (strncmp(filename, "/dev/stdin", 11) == 0 || strncmp(filename, "-", 2) == 0);
    state->packet_buffer = NULL;
    state->buffer_size = 0;
    
    // Free the filename from duckdb_get_varchar
    duckdb_free((void *)filename);
    
    // Set the bind data
    duckdb_bind_set_bind_data(info, state, PcapReaderBindDataFree);
    
    // Add return columns
    duckdb_logical_type ubigint_type = duckdb_create_logical_type(DUCKDB_TYPE_UBIGINT);
    duckdb_logical_type uinteger_type = duckdb_create_logical_type(DUCKDB_TYPE_UINTEGER);
    duckdb_logical_type blob_type = duckdb_create_logical_type(DUCKDB_TYPE_BLOB);
    
    duckdb_bind_add_result_column(info, "timestamp_ns", ubigint_type);
    duckdb_bind_add_result_column(info, "original_len", uinteger_type);
    duckdb_bind_add_result_column(info, "capture_len", uinteger_type);
    duckdb_bind_add_result_column(info, "data", blob_type);
    
    duckdb_destroy_logical_type(&ubigint_type);
    duckdb_destroy_logical_type(&uinteger_type);
    duckdb_destroy_logical_type(&blob_type);
    
    duckdb_destroy_value(&filename_value);
}

// Init function for the pcap reader
static void PcapReaderInit(duckdb_init_info info) {
    pcap_reader_state_t *bind_state = (pcap_reader_state_t *)duckdb_init_get_bind_data(info);
    
    // Create a new state for this init
    pcap_reader_state_t *state = (pcap_reader_state_t *)duckdb_malloc(sizeof(pcap_reader_state_t));
    if (!state) {
        duckdb_init_set_error(info, "Failed to allocate memory for init state");
        return;
    }
    
    // Copy relevant data from bind state
    state->filename = bind_state->filename;  // Just reference, don't copy
    state->needs_swap = 0;
    state->is_nanosecond = 0;
    state->is_stdin = bind_state->is_stdin;
    state->packet_buffer = NULL;
    state->buffer_size = 0;
    
    // Open the pcap file or use stdin
    if (state->is_stdin) {
        state->file = stdin;
#ifdef _WIN32
        // Set stdin to binary mode on Windows
        _setmode(_fileno(stdin), _O_BINARY);
#endif
    } else {
#ifdef _WIN32
        errno_t err = fopen_s(&state->file, state->filename, "rb");
        if (err != 0 || !state->file) {
            duckdb_free(state);
            duckdb_init_set_error(info, "Failed to open pcap file");
            return;
        }
#else
        state->file = fopen(state->filename, "rb");
        if (!state->file) {
            duckdb_free(state);
            duckdb_init_set_error(info, "Failed to open pcap file");
            return;
        }
#endif
    }
    
    // Read the file header
    if (fread(&state->file_header, sizeof(pcap_file_header_t), 1, state->file) != 1) {
        if (!state->is_stdin) {
            fclose(state->file);
        }
        duckdb_free(state);
        duckdb_init_set_error(info, "Failed to read pcap file header");
        return;
    }
    
    // Check magic number and determine if we need to swap bytes and timestamp precision
    if (state->file_header.magic_number == PCAP_MAGIC_NATIVE) {
        state->needs_swap = 0;
        state->is_nanosecond = 0;
    } else if (state->file_header.magic_number == PCAP_MAGIC_SWAPPED) {
        state->needs_swap = 1;
        state->is_nanosecond = 0;
        // Swap the header fields we'll use
        state->file_header.snaplen = swap32(state->file_header.snaplen);
    } else if (state->file_header.magic_number == PCAP_MAGIC_NANO_NATIVE) {
        state->needs_swap = 0;
        state->is_nanosecond = 1;
    } else if (state->file_header.magic_number == PCAP_MAGIC_NANO_SWAPPED) {
        state->needs_swap = 1;
        state->is_nanosecond = 1;
        // Swap the header fields we'll use
        state->file_header.snaplen = swap32(state->file_header.snaplen);
    } else {
        if (!state->is_stdin) {
            fclose(state->file);
        }
        duckdb_free(state);
        duckdb_init_set_error(info, "Invalid pcap file magic number");
        return;
    }
    
    // Pre-allocate packet buffer based on snaplen
    state->buffer_size = state->file_header.snaplen;
    state->packet_buffer = (uint8_t *)duckdb_malloc(state->buffer_size);
    if (!state->packet_buffer) {
        if (!state->is_stdin) {
            fclose(state->file);
        }
        duckdb_free(state);
        duckdb_init_set_error(info, "Failed to allocate packet buffer");
        return;
    }
    
    duckdb_init_set_init_data(info, state, PcapReaderInitDataFree);
}

// Function to read packets from the pcap file
static void PcapReaderFunction(duckdb_function_info info, duckdb_data_chunk output) {
    pcap_reader_state_t *state = (pcap_reader_state_t *)duckdb_function_get_init_data(info);
    
    if (!state || !state->file) {
        duckdb_data_chunk_set_size(output, 0);
        return;
    }
    
    // Get output vectors
    duckdb_vector timestamp_vec = duckdb_data_chunk_get_vector(output, 0);
    duckdb_vector original_len_vec = duckdb_data_chunk_get_vector(output, 1);
    duckdb_vector capture_len_vec = duckdb_data_chunk_get_vector(output, 2);
    duckdb_vector data_vec = duckdb_data_chunk_get_vector(output, 3);
    
    uint64_t *timestamp_data = (uint64_t *)duckdb_vector_get_data(timestamp_vec);
    uint32_t *original_len_data = (uint32_t *)duckdb_vector_get_data(original_len_vec);
    uint32_t *capture_len_data = (uint32_t *)duckdb_vector_get_data(capture_len_vec);
    
    idx_t row_count = 0;
    idx_t max_rows = duckdb_vector_size();
    
    while (row_count < max_rows && !feof(state->file)) {
        pcap_packet_header_t packet_header;
        
        // Read packet header
        if (fread(&packet_header, sizeof(pcap_packet_header_t), 1, state->file) != 1) {
            break;
        }
        
        // Swap bytes if needed
        if (state->needs_swap) {
            packet_header.ts_sec = swap32(packet_header.ts_sec);
            packet_header.ts_usec = swap32(packet_header.ts_usec);
            packet_header.caplen = swap32(packet_header.caplen);
            packet_header.len = swap32(packet_header.len);
        }
        
        // Convert timestamp to nanoseconds
        uint64_t timestamp_ns;
        if (state->is_nanosecond) {
            // ts_usec field contains nanoseconds in nanosecond-precision files
            timestamp_ns = ((uint64_t)packet_header.ts_sec * 1000000000ULL) + 
                          (uint64_t)packet_header.ts_usec;
        } else {
            // ts_usec field contains microseconds in microsecond-precision files
            timestamp_ns = ((uint64_t)packet_header.ts_sec * 1000000000ULL) + 
                          ((uint64_t)packet_header.ts_usec * 1000ULL);
        }
        
        // Reallocate buffer if packet is larger than current buffer
        if (packet_header.caplen > state->buffer_size) {
            uint8_t *new_buffer = (uint8_t *)duckdb_malloc(packet_header.caplen);
            if (!new_buffer) {
                break;
            }
            duckdb_free(state->packet_buffer);
            state->packet_buffer = new_buffer;
            state->buffer_size = packet_header.caplen;
        }
        
        // Read packet data into reusable buffer
        if (fread(state->packet_buffer, 1, packet_header.caplen, state->file) != packet_header.caplen) {
            break;
        }
        
        // Set output values
        timestamp_data[row_count] = timestamp_ns;
        original_len_data[row_count] = packet_header.len;
        capture_len_data[row_count] = packet_header.caplen;
        
        // Set blob data - DuckDB copies the data internally
        duckdb_vector_assign_string_element_len(data_vec, row_count, (const char *)state->packet_buffer, packet_header.caplen);
        
        row_count++;
    }
    
    duckdb_data_chunk_set_size(output, row_count);
}

// Register the pcap reader function
void RegisterPcapReaderFunction(duckdb_connection connection) {
    // Create table function
    duckdb_table_function function = duckdb_create_table_function();
    duckdb_table_function_set_name(function, "read_pcap");
    
    // Add parameter for filename
    duckdb_logical_type varchar_type = duckdb_create_logical_type(DUCKDB_TYPE_VARCHAR);
    duckdb_table_function_add_parameter(function, varchar_type);
    duckdb_destroy_logical_type(&varchar_type);
    
    // Set function callbacks
    duckdb_table_function_set_bind(function, PcapReaderBind);
    duckdb_table_function_set_init(function, PcapReaderInit);
    duckdb_table_function_set_function(function, PcapReaderFunction);
    
    // Register the function
    duckdb_register_table_function(connection, function);
    duckdb_destroy_table_function(&function);
}
