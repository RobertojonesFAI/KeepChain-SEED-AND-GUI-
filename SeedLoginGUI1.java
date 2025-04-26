import java.awt.*;
import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.Random;
import javax.crypto.*;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import javax.swing.*;

/**
 * KeepChain initial prototype, generate user using seed phrases, then use program to manage stored passwords under your user.
 * 
 * @Author Roberto Jones, Travis Goodrich.
 */

public class SeedLoginGUI1 {
    private static final String SEED_FILE = "generatedSeed.txt";
    private static final String USERS_DIR = "users";
    private static final String VALIDATION_STRING = "VALID";
    private static List<String> wordList;
    private static final Random random = new Random();
    private static JFrame frame;
    private static SecretKey currentKey;
    private static File currentUserFile;
    private static final String SECRET_KEY = "1234567890123456";

    public static void main(String[] args) {
        SwingUtilities.invokeLater(SeedLoginGUI1::createAndShowGUI);
    }

    private static void createAndShowGUI() {
        frame = new JFrame("Seed Phrase Login");
        frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        frame.setSize(400, 300);

        File usersDir = new File(USERS_DIR);
        if (!usersDir.exists()) usersDir.mkdir();

        JPanel panel = new JPanel();
        panel.setLayout(new GridLayout(4, 1, 10, 10));

        JButton createButton = new JButton("Generate User (Generate Seed)");
        JButton loginButton = new JButton("Log In");

        panel.add(new JLabel("Welcome. Choose an option:"));
        panel.add(createButton);
        panel.add(loginButton);

        frame.getContentPane().add(panel);
        frame.setLocationRelativeTo(null);
        frame.setVisible(true);

        createButton.addActionListener(e -> showGeneratedSeed());
        loginButton.addActionListener(e -> showLoginScreen());
    }

    private static void showGeneratedSeed() {
        List<String> generatedSeed = generateSeed();
        String seedString = String.join(" ", generatedSeed);

        saveSeed(seedString);

        JTextArea seedTextArea = new JTextArea(seedString);
        seedTextArea.setEditable(false);
        seedTextArea.setLineWrap(true);
        seedTextArea.setWrapStyleWord(true);

        JScrollPane scrollPane = new JScrollPane(seedTextArea);
        scrollPane.setPreferredSize(new Dimension(300, 100));

        JOptionPane.showMessageDialog(frame, scrollPane, "Your seed words (copy them somewhere safe):", JOptionPane.INFORMATION_MESSAGE);
    }

    private static void showLoginScreen() {
        JTextArea seedInput = new JTextArea(5, 20);
        JScrollPane scrollPane = new JScrollPane(seedInput);

        int result = JOptionPane.showConfirmDialog(frame, scrollPane, "Enter your seed phrase", JOptionPane.OK_CANCEL_OPTION);

        if (result == JOptionPane.OK_OPTION) {
            String seedPhrase = seedInput.getText().trim();
            String normalizedSeed = normalizeSeedPhrase(seedPhrase);
            if (normalizedSeed.isEmpty()) {
                JOptionPane.showMessageDialog(frame, "Seed phrase cannot be empty.", "Error", JOptionPane.ERROR_MESSAGE);
                return;
            }

            String hash = getHash(normalizedSeed);
            File userFile = new File(USERS_DIR + File.separator + hash + ".dat");

            if (userFile.exists()) {
                currentKey = login(userFile, normalizedSeed);
                if (currentKey != null) {
                    currentUserFile = userFile;
                    JOptionPane.showMessageDialog(frame, "Login successful!", "Success", JOptionPane.INFORMATION_MESSAGE);
                    showPasswordManager();
                } else {
                    JOptionPane.showMessageDialog(frame, "Invalid seed phrase.", "Error", JOptionPane.ERROR_MESSAGE);
                }
            } else {
                try {
                    currentKey = createUser(userFile, normalizedSeed);
                    currentUserFile = userFile;
                    JOptionPane.showMessageDialog(frame, "Account created successfully!", "Success", JOptionPane.INFORMATION_MESSAGE);
                    showPasswordManager();
                } catch (Exception e) {
                    JOptionPane.showMessageDialog(frame, "Error creating account: " + e.getMessage(), "Error", JOptionPane.ERROR_MESSAGE);
                }
            }
        }
    }

    private static void showPasswordManager() {
        JFrame managerFrame = new JFrame("Password Manager");
        managerFrame.setSize(400, 300);
        managerFrame.setDefaultCloseOperation(JFrame.DISPOSE_ON_CLOSE);

        JPanel panel = new JPanel(new GridLayout(5, 1, 10, 10));
        JButton addButton = new JButton("Add Password");
        //JButton viewEncryptedButton = new JButton("View Encrypted Passwords");
        JButton viewDecryptedButton = new JButton("Manage Passwords");
        JButton deleteDataButton = new JButton("Delete Data and Exit");

        panel.add(new JLabel("Password Manager Options:"));
        panel.add(addButton);
        //panel.add(viewEncryptedButton);
        panel.add(viewDecryptedButton);
        panel.add(deleteDataButton);

        managerFrame.getContentPane().add(panel);
        managerFrame.setLocationRelativeTo(null);
        managerFrame.setVisible(true);

        addButton.addActionListener(e -> addPassword());
        //viewEncryptedButton.addActionListener(e -> viewEncryptedPasswords());
        viewDecryptedButton.addActionListener(e -> viewDecryptedPasswords());
        deleteDataButton.addActionListener(e -> {
            currentUserFile.delete();
            managerFrame.dispose();
            frame.dispose();
            System.exit(0);
        });
    }

    private static void addPassword() {

    JTextField websiteField = new JTextField(20);
    JTextField usernameField = new JTextField(20);
    JPasswordField passwordField = new JPasswordField(20);


    JPanel inputPanel = new JPanel(new GridLayout(3, 2));
    inputPanel.add(new JLabel("Website:" ));
    inputPanel.add(websiteField);
    inputPanel.add(new JLabel("Username:" ));
    inputPanel.add(usernameField);
    inputPanel.add(new JLabel("Password:" ));
    inputPanel.add(passwordField);

    int result = JOptionPane.showConfirmDialog(frame, inputPanel, "Enter Credential", JOptionPane.OK_CANCEL_OPTION);
    if (result == JOptionPane.OK_OPTION) {
        String website = websiteField.getText().trim();
        String username = usernameField.getText().trim();
        char[] passwordChars = passwordField.getPassword();
        String password = new String(passwordChars).trim();
        Arrays.fill(passwordChars, '0'); 

        if (website.isEmpty() || username.isEmpty() || password.isEmpty()) {
            JOptionPane.showMessageDialog(frame, "All fields must be filled.", "Error", JOptionPane.ERROR_MESSAGE);
            return;
        }


        String credential = website + "|" + username + "|" + password;
        try {
            addPasswordToFile(currentUserFile, currentKey, credential);
            JOptionPane.showMessageDialog(frame, "Credential added successfully!", "Success", JOptionPane.INFORMATION_MESSAGE);
        } catch (Exception e) {
            JOptionPane.showMessageDialog(frame, "Error adding credential: " + e.getMessage(), "Error", JOptionPane.ERROR_MESSAGE);
        }
    }
}

    /**private static void viewEncryptedPasswords() {
        try {
            StringBuilder encryptedPasswords = new StringBuilder();
            try (BufferedReader reader = new BufferedReader(new FileReader(currentUserFile))) {
                reader.readLine(); // Skip salt
                reader.readLine(); // Skip validation line
                String line;
                while ((line = reader.readLine()) != null) {
                    encryptedPasswords.append(line).append("\n");
                }
            }
            JTextArea textArea = new JTextArea(encryptedPasswords.toString());
            textArea.setEditable(false);
            JScrollPane scrollPane = new JScrollPane(textArea);
            scrollPane.setPreferredSize(new Dimension(300, 200));
            JOptionPane.showMessageDialog(frame, scrollPane, "Encrypted Passwords", JOptionPane.INFORMATION_MESSAGE);
        } catch (IOException e) {
            JOptionPane.showMessageDialog(frame, "Error reading encrypted passwords: " + e.getMessage(), "Error", JOptionPane.ERROR_MESSAGE);
        }
    }*/

     private static void viewDecryptedPasswords() {
        try {
            StringBuilder decryptedPasswords = new StringBuilder();
            try (BufferedReader reader = new BufferedReader(new FileReader(currentUserFile))) {
                reader.readLine(); 
                reader.readLine(); 
                String line;
                while ((line = reader.readLine()) != null) {
                    String[] parts = line.split(":");
                    if (parts.length == 2) {
                        byte[] iv = Base64.getDecoder().decode(parts[0]);
                        byte[] cipherText = Base64.getDecoder().decode(parts[1]);
                        String decrypted = decrypt(currentKey, iv, cipherText);
                        decryptedPasswords.append(decrypted).append("\n");
                    }
                }
            }
            JTextArea textArea = new JTextArea(decryptedPasswords.toString());
            textArea.setEditable(false);
            JScrollPane scrollPane = new JScrollPane(textArea);
            scrollPane.setPreferredSize(new Dimension(300, 200));
            JOptionPane.showMessageDialog(frame, scrollPane, "Decrypted Passwords", JOptionPane.INFORMATION_MESSAGE);
        } catch (Exception e) {
            JOptionPane.showMessageDialog(frame, "Error decrypting passwords: " + e.getMessage(), "Error", JOptionPane.ERROR_MESSAGE);
        }
    }

    private static List<String> generateSeed() {
        if (wordList.isEmpty()) {
            throw new IllegalStateException("Word list is empty. Ensure words.txt is properly loaded.");
        }
        List<String> seed = new java.util.ArrayList<>();
        for (int i = 0; i < 12; i++) {
            seed.add(wordList.get(random.nextInt(wordList.size())));
        }
        return seed;
    }

    static {
        try {
            wordList = Files.readAllLines(Paths.get("words.txt"));
        } catch (IOException e) {
            wordList = java.util.Collections.emptyList();
            System.err.println("Error loading words from file: " + e.getMessage());
        }
    }

    private static void saveSeed(String seed) {
        try {
           
            String encryptedSeed = encrypt(seed, SECRET_KEY);
    
            
            try (BufferedWriter writer = new BufferedWriter(new FileWriter(SEED_FILE, true))) {
                writer.write(encryptedSeed);
                writer.newLine();
            }
        } catch (Exception e) {
            System.err.println("Error saving seed: " + e.getMessage());
        }
    }
    
    private static String encrypt(String data, String secretKey) throws Exception {
        SecretKey key = new SecretKeySpec(secretKey.getBytes(), "AES");
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        byte[] encryptedBytes = cipher.doFinal(data.getBytes());
        return Base64.getEncoder().encodeToString(encryptedBytes);
    }

    private static String normalizeSeedPhrase(String seedPhrase) {
        String[] words = seedPhrase.trim().split("\\s+");
        return String.join(" ", words);
    }

    private static String getHash(String seedPhrase) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(seedPhrase.getBytes());
            StringBuilder hexString = new StringBuilder();
            for (byte b : hash) {
                String hex = Integer.toHexString(0xff & b);
                if (hex.length() == 1) hexString.append('0');
                hexString.append(hex);
            }
            return hexString.toString();
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("SHA-256 not available", e);
        }
    }

    private static SecretKey createUser(File userFile, String seedPhrase) throws Exception {
        byte[] saltBytes = new byte[16];
        new SecureRandom().nextBytes(saltBytes);
        String salt = Base64.getEncoder().encodeToString(saltBytes);
        SecretKey key = getKeyFromPassword(seedPhrase, salt);

        byte[] iv = generateIvBytes();
        String encryptedValidation = encrypt(key, iv, VALIDATION_STRING);

        try (BufferedWriter writer = new BufferedWriter(new FileWriter(userFile))) {
            writer.write(salt);
            writer.newLine();
            writer.write(Base64.getEncoder().encodeToString(iv) + ":" + encryptedValidation);
            writer.newLine();
        }
        return key;
    }

    private static SecretKey login(File userFile, String seedPhrase) {
        try (BufferedReader reader = new BufferedReader(new FileReader(userFile))) {
            String saltLine = reader.readLine();
            if (saltLine == null) return null;
            String validationLine = reader.readLine();
            if (validationLine == null) return null;

            String salt = saltLine;
            SecretKey key = getKeyFromPassword(seedPhrase, salt);
            String[] parts = validationLine.split(":");
            if (parts.length != 2) return null;

            byte[] iv = Base64.getDecoder().decode(parts[0]);
            byte[] cipherText = Base64.getDecoder().decode(parts[1]);
            String decrypted = decrypt(key, iv, cipherText);
            return decrypted.equals(VALIDATION_STRING) ? key : null;
        } catch (Exception e) {
            return null;
        }
    }

    private static void addPasswordToFile(File userFile, SecretKey key, String password) throws Exception {
        byte[] iv = generateIvBytes();
        String encryptedPassword = encrypt(key, iv, password);
        try (BufferedWriter writer = new BufferedWriter(new FileWriter(userFile, true))) {
            writer.write(Base64.getEncoder().encodeToString(iv) + ":" + encryptedPassword);
            writer.newLine();
        }
    }

    private static String encrypt(SecretKey key, byte[] iv, String input) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        GCMParameterSpec spec = new GCMParameterSpec(128, iv);
        cipher.init(Cipher.ENCRYPT_MODE, key, spec);
        byte[] cipherText = cipher.doFinal(input.getBytes());
        return Base64.getEncoder().encodeToString(cipherText);
    }

    private static String decrypt(SecretKey key, byte[] iv, byte[] cipherText) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        GCMParameterSpec spec = new GCMParameterSpec(128, iv);
        cipher.init(Cipher.DECRYPT_MODE, key, spec);
        byte[] plainText = cipher.doFinal(cipherText);
        return new String(plainText);
    }

    private static byte[] generateIvBytes() {
        byte[] iv = new byte[12];
        new SecureRandom().nextBytes(iv);
        return iv;
    }

    private static SecretKey getKeyFromPassword(String password, String salt) throws NoSuchAlgorithmException, InvalidKeySpecException {
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        KeySpec spec = new PBEKeySpec(password.toCharArray(), Base64.getDecoder().decode(salt), 65536, 256);
        return new SecretKeySpec(factory.generateSecret(spec).getEncoded(), "AES");
    }
}