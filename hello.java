// class Computer {

//     public Computer() {
//         System.out.println("this is constructor");
//     }

//     private int age;
//     private String name;

//     public int getAge() {
//         return age;
//     }

//     public void setAge(int age) {
//         this.age = age;
//     }

//     public String getName() {
//         return name;
//     }

//     public void setName(String name) {
//         this.name = name;
//     }

// }

// class Amount {
//     public void withdraw(double amount) {
//         double balance = 90;
//         if (amount > balance) {
//             throw new RuntimeException("Insufficient funds");

//         }
//         balance = balance - amount;
//         System.out.println("balance");
//     }

//     public void processWithdrawal(double amount) {
//         withdraw(amount);
//         System.out.println("Withdrawal successful");
//     }

// }
class Password {
    public boolean checkPassword(String entered, String stored) {
        return entered.equals(stored);
    }
}

public boolean validateOtp(String enteredOtp, String actualOtp) {
    if (enteredOtp == null || actualOtp == null) {
        return false;
    }
    if (enteredOtp.length() != actualOtp.length()) {
        return false;
    }
    int result = 0;
    for (int i = 0; i < enteredOtp.length(); i++) {
        result |= enteredOtp.charAt(i) ^ actualOtp.charAt(i);
    }
    return result == 0;
}

public class hello {

    public static void main(String bla[]) {

        // Computer obj = new Computer();
        // obj.setAge(4);

        // System.out.println(obj.getAge());
        // Amount obj = new Amount();
        // obj.withdraw(100.0);
        // obj.processWithdrawal(100.0);

        // 1. Created using String literals
        String adminRole1 = "ADMIN";
        String adminRole2 = "ADMIN";

        // 2. Created using the 'new' keyword (simulating user input)
        String userProvidedRole = new String("ADMIN");

        System.out.println("--- Using == (Memory Address) ---");
        System.out.println(adminRole1 == adminRole2); // TRUE: Both point to the same object in the String Pool
        System.out.println(adminRole1 == userProvidedRole); // FALSE: Different memory addresses!

        System.out.println("\n--- Using .equals() (Content) ---");
        System.out.println(adminRole1.equals(adminRole2)); // TRUE: "ADMIN" is "ADMIN"
        System.out.println(adminRole1.equals(userProvidedRole)); // TRUE: "ADMIN" is "ADMIN"
        System.out.println("------------------------------");
        String a = "hello";
        String b = "hel" + "lo";
        String c = new String("hello");
        System.out.println(a == b);
        System.out.println(a == c);
        System.out.println(a.equals(c));
        Password obj2 = new Password();
        System.out.println("------------------------------");
        System.out.println(obj2.checkPassword(a, b));
        System.out.println(obj2.checkPassword(a, c));
        System.out.println(obj2.checkPassword(b, c));
        System.out.println("------------------------------");

        String suffix = "min";
        String role = "ad" + suffix;
        String literal = "admin";
        System.out.println(role == literal);

        String bla4 = "admin";
        String bla5 = "admin";
        System.out.println(bla4 = bla5);

        System.out.println("------------------------------");
        System.out.println("------------------------------");

        final String PREFIX = "USR";
        final String SUFFIX = "001";
        String id1 = PREFIX + SUFFIX;
        String id2 = "USR001";
        System.out.println(id1 == id2);

        System.out.println("------------------------------");
        validateOtp obj4 = new validateOtp();
        obj4.validateOtp("blaaaa", "blaaaa");
    }
}