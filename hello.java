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

class Amount {
    public void withdraw(double amount) {
        double balance = 90;
        if (amount > balance) {
            throw new RuntimeException("Insufficient funds");

        }
        balance = balance - amount;
        System.out.println("balance");
    }

    public void processWithdrawal(double amount) {
        withdraw(amount);
        System.out.println("Withdrawal successful");
    }

}

public class hello {

    public static void main(String a[]) {

        // Computer obj = new Computer();
        // obj.setAge(4);

        // System.out.println(obj.getAge());
        Amount obj = new Amount();
        obj.withdraw(100.0);
        obj.processWithdrawal(100.0);

    }
}