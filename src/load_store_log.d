module load_store_log_;

import std.stdio;

private static File* loadStoreLog = null;

File* load_store_log() {
    if (loadStoreLog is null) {
        loadStoreLog = new File("load_store_log.txt", "w");
    }
    return loadStoreLog;
}
