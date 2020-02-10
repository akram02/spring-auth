package info.nitex.auth.exception;

public class AccountEmailAlreadyUsedException extends BadRequestAlertException {

    private static final long serialVersionUID = 1L;

    public AccountEmailAlreadyUsedException() {
        super(ErrorConstants.EMAIL_ALREADY_USED_TYPE, "Email is already in use!", "userManagement", "emailexists");
    }
}
