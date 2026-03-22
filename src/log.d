module log;

import std.stdio;
import std.file;

private static File* load_store_log_ptr = null;

static string __log_dir__ = "./logs/";

File* load_store_log() {
    if (load_store_log_ptr is null) {
        load_store_log_ptr = new File(__log_dir__ ~ "load_store_log.txt", "w");
    }
    return load_store_log_ptr;
}

private static File* pc_log_ptr = null;

File* pc_log() {
    if (!exists(__log_dir__)) 
        mkdir(__log_dir__); 
    if (pc_log_ptr is null) {
        pc_log_ptr = new File(__log_dir__ ~ "pc_log.txt", "w");
    }
    return pc_log_ptr;
}

private static File* stack_log_ptr = null;

File* stack_log() {
    if (stack_log_ptr is null) {
        stack_log_ptr = new File(__log_dir__ ~ "stack_log.txt", "w");
    }
    return stack_log_ptr;
}

private static File* uart_log_ptr = null;

File* uart_log() {
    if (uart_log_ptr is null) {
        uart_log_ptr = new File(__log_dir__ ~ "uart_log.txt", "w");
    }
    return uart_log_ptr;
}

private static File* gpio_log_ptr = null;

File* gpio_log() {
    if (gpio_log_ptr is null) {
        gpio_log_ptr = new File(__log_dir__ ~ "gpio_log.txt", "w");
    }
    return gpio_log_ptr;
}
