// =================
//  RAM Mem Section
// =================

struct ram_mem_section {
	ubyte[128 * 1024] cells;

    const(ubyte) read_byte(size_t index) const {
    	index -= ram_origin;
        return cells[index];
    }

    const(ushort) read_half_word(size_t index) {
    	index -= ram_origin;
    	ushort res = (cells[index + 1] << 8) | cells[index];
    	return res;
    }

    const(uint) read_word(size_t index) {
    	index -= ram_origin;
    	uint res = (cells[index + 3] << 24) | 
    	           (cells[index + 2] << 16) | 
    	           (cells[index + 1] <<  8) | 
    	            cells[index    ];
    	return res;
    }

    void write_byte(size_t index, ubyte val) {
    	index -= ram_origin;
    	cells[index] = val;
    }

    void write_half_word(size_t index, ushort val) {
    	index -= ram_origin;
    	cells[index + 1] = (val >> 8) & 0xff;
    	cells[index] =      val       & 0xff;
    }

    void write_word(size_t index, uint val) {
    	index -= ram_origin;
    	cells[index + 3] = (val >> 24) & 0xff;
    	cells[index + 2] = (val >> 16) & 0xff;
    	cells[index + 1] = (val >>  8) & 0xff;
    	cells[index] =      val        & 0xff;
    }

    static enum ram_origin = 0x20000000;
}

__gshared ubyte[1024 * 1024] g_flash;

// ===================
//  Flash Mem Section
// ===================

struct flash_mem_section {
    const(ubyte) read_byte(size_t index) const {
    	index -= flash_origin;
        return g_flash[index];
    }

    const(ushort) read_half_word(size_t index) const {
    	index -= flash_origin;
    	ushort res = (g_flash[index + 1] << 8) | g_flash[index];
    	return res;
    }

    const(uint) read_word(size_t index) const {
    	index -= flash_origin;
    	uint res = (g_flash[index + 3] << 24) | 
    	           (g_flash[index + 2] << 16) | 
    	           (g_flash[index + 1] <<  8) |  
    	            g_flash[index];
    	return res;
    }

    static void write_word(size_t index, uint val) {
       	index -= flash_origin;
    	g_flash[index + 3] = (val >> 24) & 0xff;
    	g_flash[index + 2] = (val >> 16) & 0xff;
    	g_flash[index + 1] = (val >>  8) & 0xff;
    	g_flash[index    ] =  val        & 0xff;
    }

    enum flash_origin = 0x8000000;
}

// ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
unittest {
    flash_mem_section flash;
    flash.write_word(flash_mem_section.flash_origin, 32);
    uint read_value = flash.read_word(flash_mem_section.flash_origin);
    assert(read_value == 32, "Failed to read word from flash");
}