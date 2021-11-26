#![crate_type = "staticlib"]
#![no_std]

#[repr(C)]
pub struct Args {
    pub a: i32,
    pub b: i32,
    pub result: i32,
}

#[no_mangle]
extern "C" {
    static mut _counter: i32;
    static mut othercounter: i32;
}

#[no_mangle]
pub extern "C" fn add(args: *mut Args) -> i64 {

    let refargs = unsafe { &mut *(args) };

    /*
    unsafe {
        a = (*args).a;
        b = (*args).b;
    }
    */

    refargs.result = refargs.a + refargs.b;

    unsafe {
        _counter += othercounter;
    }

    print("Hello from Rust!\n");
    print("Hello again!\n");
    print("💩\n");
    print("This is a very long string and I need to know what is happening!\n");

    return 0;
}

fn print(s: &str) {
    let size = s.len();
    let arr;
    let ptr;
    unsafe {
        ptr = malloc(size + 1);
        arr = core::slice::from_raw_parts_mut(ptr , size + 1);
    };

    for (index, byte) in s.bytes().enumerate() {
        arr[index] = byte;
    }
    arr[size] = 0;

    unsafe {
        ocall_print_string(arr.as_ptr());
        //ocall_print_string(s.as_ptr());
    }

    unsafe {
        free(ptr);
    }
}

extern "C" {
    fn abort() -> !;
    fn ocall_print_string(s: *const u8);
    fn malloc(size: usize) -> *mut u8;
    fn free(ptr: *const u8);
//    static mut _counter: i32;
//    #[panic_handler] fn panic(arg: &core::panic::PanicInfo) -> !;
}

#[panic_handler] extern fn panic(_arg: &core::panic::PanicInfo) -> ! { unsafe { abort() } }
