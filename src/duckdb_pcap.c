#include "duckdb_extension.h"
#include "pcap_reader.h"

DUCKDB_EXTENSION_ENTRYPOINT(duckdb_connection connection, duckdb_extension_info info, struct duckdb_extension_access *access) {
	// Register pcap reader function
	RegisterPcapReaderFunction(connection);

	// Return true to indicate successful initialization
	return true;
}
