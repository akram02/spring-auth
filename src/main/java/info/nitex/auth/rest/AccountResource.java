package info.nitex.auth.rest;


import info.nitex.auth.exception.AccountEmailAlreadyUsedException;
import info.nitex.auth.exception.AccountResourceException;
import info.nitex.auth.exception.EmailNotFoundException;
import info.nitex.auth.exception.InvalidPasswordException;
import info.nitex.auth.model.*;
import info.nitex.auth.security.SecurityUtils;
import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpServletRequest;
import javax.validation.Valid;
import java.util.Optional;

@RestController
@RequestMapping("/api")
public class AccountResource {

    private final Logger log = LoggerFactory.getLogger(AccountResource.class);

    private final UserRepository userRepository;

    private final UserService userService;

    private final MailService mailService;

    public AccountResource(UserRepository userRepository, UserService userService, MailService mailService) {
        this.userRepository = userRepository;
        this.userService = userService;
        this.mailService = mailService;
    }

    @PostMapping("/register")
    @ResponseStatus(HttpStatus.CREATED)
    public void registerAccount(@Valid @RequestBody ManagedUserVM managedUserVM) {
        if (errorCheckPasswordLength(managedUserVM.getPassword())) {
            throw new InvalidPasswordException();
        }
        User user = userService.registerUser(managedUserVM, managedUserVM.getPassword());
        mailService.sendActivationEmail(user);
    }

    @GetMapping("/activate")
    public void activateAccount(@RequestParam(value = "key") String key) {
        Optional<User> user = userService.activateRegistration(key);
        if (!user.isPresent()) {
            throw new AccountResourceException("No user was found for this activation key");
        }
    }


    @GetMapping("/authenticate")
    public String isAuthenticated(HttpServletRequest request) {
        log.debug("check if the current user is authenticated");
        return request.getRemoteUser();
    }

    @GetMapping("/account")
    public UserDTO getAccount() {
        return userService.getUserWithAuthorities()
                .map(UserDTO::new)
                .orElseThrow(() -> new AccountResourceException("User could not be found"));
    }

    @PostMapping("/account")
    public void saveAccount(@Valid @RequestBody UserDTO userDTO) {
        String userLogin = SecurityUtils.getCurrentUserLogin().orElseThrow(() -> new AccountResourceException("Current user login not found"));
        Optional<User> existingUser = userRepository.findOneByEmailIgnoreCase(userDTO.getEmail());
        if (existingUser.isPresent() && (!existingUser.get().getLogin().equalsIgnoreCase(userLogin))) {
            throw new AccountEmailAlreadyUsedException();
        }
        Optional<User> user = userRepository.findOneByLogin(userLogin);
        if (!user.isPresent()) {
            throw new AccountResourceException("User could not be found");
        }
        userService.updateUser(userDTO.getFirstName(), userDTO.getLastName(), userDTO.getEmail(),
                userDTO.getLangKey(), userDTO.getImageUrl());
    }

    @PostMapping(path = "/account/change-password")
    public void changePassword(@RequestBody PasswordChangeDTO passwordChangeDto) {
        if (errorCheckPasswordLength(passwordChangeDto.getNewPassword())) {
            throw new InvalidPasswordException();
        }
        userService.changePassword(passwordChangeDto.getCurrentPassword(), passwordChangeDto.getNewPassword());
    }

    @PostMapping(path = "/account/reset-password/init")
    public void requestPasswordReset(@RequestBody String mail) {
        mailService.sendPasswordResetMail(
                userService.requestPasswordReset(mail)
                        .orElseThrow(EmailNotFoundException::new)
        );
    }

    @PostMapping(path = "/account/reset-password/finish")
    public void finishPasswordReset(@RequestBody KeyAndPasswordVM keyAndPassword) {
        if (errorCheckPasswordLength(keyAndPassword.getNewPassword())) {
            throw new InvalidPasswordException();
        }
        Optional<User> user =
                userService.completePasswordReset(keyAndPassword.getNewPassword(), keyAndPassword.getKey());

        if (!user.isPresent()) {
            throw new AccountResourceException("No user was found for this reset key");
        }
    }

    private static boolean errorCheckPasswordLength(String password) {
        return StringUtils.isEmpty(password) ||
                password.length() < ManagedUserVM.PASSWORD_MIN_LENGTH ||
                password.length() > ManagedUserVM.PASSWORD_MAX_LENGTH;
    }
}
