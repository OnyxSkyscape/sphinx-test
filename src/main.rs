use sphinx::generate_password;

fn main() {
    let pwd = "hello!";
    let spwd = generate_password(pwd.to_owned());
    println!("{:?}", spwd);
}
