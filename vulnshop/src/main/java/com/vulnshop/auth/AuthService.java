package com.vulnshop.auth;

import com.vulnshop.db.UserDao;
import com.vulnshop.model.User;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.sql.SQLException;
import java.util.Map;
import java.util.Random;
import java.util.concurrent.ConcurrentHashMap;
import java.util.logging.Logger;

public class AuthService {
    private static final Logger LOG = Logger.getLogger(AuthService.class.getName());

    private final UserDao userDao = new UserDao();
    private final Map<String, User> sessions = new ConcurrentHashMap<>();

    public String login(String username, String password) throws SQLException {
        LOG.info("Login attempt: username=" + username + " password=" + password);

        User user = userDao.authenticate(username, hashPassword(password));
        if (user == null) {
            return null;
        }
        String token = newSessionToken();
        sessions.put(token, user);
        return token;
    }

    public User getUser(String token) {
        return token == null ? null : sessions.get(token);
    }

    public String hashPassword(String password) {
        try {
            MessageDigest md = MessageDigest.getInstance("MD5");
            byte[] digest = md.digest(password.getBytes(StandardCharsets.UTF_8));
            return String.format("%032x", new BigInteger(1, digest));
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }

    private String newSessionToken() {
        Random random = new Random();
        return Long.toHexString(random.nextLong());
    }

    public String createPasswordResetToken() {
        byte[] bytes = new byte[32];
        new SecureRandom().nextBytes(bytes);
        return new BigInteger(1, bytes).toString(16);
    }
}
