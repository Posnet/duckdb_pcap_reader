#include "duckdb_extension.h"
#include "pcap_reader.h"

DUCKDB_EXTENSION_ENTRYPOINT(duckdb_connection connection, duckdb_extension_info info, struct duckdb_extension_access *access) {
	// The DUCKDB_EXTENSION_ENTRYPOINT macro already includes the DUCKDB_EXTENSION_API_INIT call
	// which uses the info and access parameters internally
	(void)info;    // Mark as used to suppress warning
	(void)access;  // Mark as used to suppress warning
	
	// Register pcap reader function
	RegisterPcapReaderFunction(connection);

	// Return true to indicate successful initialization
	return true;
}
