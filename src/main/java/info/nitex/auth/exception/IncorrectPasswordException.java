package info.nitex.auth.exception;

public class IncorrectPasswordException extends RuntimeException {

    public IncorrectPasswordException() {
        super("Incorrect password");
    }

}
