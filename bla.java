class vali {

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

    public final class Money {
        private final long cents;
        private final String currency;

        public Money(long cents, String currency) {
            this.cents = cents;
            this.currency = currency;
        }

        public long getCents() {
            return cents;
        }

        public String getCurrency() {
            return currency;
        }
    }

    // public void deleteFile(String path) {
    // try {
    // Files.delete(Paths.get(path));
    // } catch (Exception e) {
    // System.out.println("Error: " + e.toString());
    // }

    // }

    public class bla {
        public static void main(String bla[]) {
            vali obj = new vali();
            // System.out.println(obj4.validateOtp("blaaa", "blaaaa"));
            // obj4.Money(500000, "doller");
            // obj4.getCents();
            // obj4.getCurrency();

            try {
                int result = 10 / 0;
                System.out.println(result);
            } catch (Exception e) {
                System.out.println("Error: " + e.toString());
            }

            // obj.deleteFile("/C:");

        }

    }

}
