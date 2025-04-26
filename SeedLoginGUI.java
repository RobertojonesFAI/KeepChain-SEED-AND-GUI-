import java.awt.*;
import java.io.BufferedWriter;
import java.io.FileWriter;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Random;
import javax.swing.*;

public class SeedLoginGUI {
    private static final String SEED_FILE = "generatedSeed.txt";
    private static List<String> wordList; // List of all words from words.txt
    private static final Random random = new Random();

    public static void main(String[] args) {
        SwingUtilities.invokeLater(SeedLoginGUI::createAndShowGUI);
    }

    private static void createAndShowGUI() {
        JFrame frame = new JFrame("Seed Phrase Login");
        frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        frame.setSize(400, 300);

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

        createButton.addActionListener(e -> showGeneratedSeed(frame));
        loginButton.addActionListener(e -> showLoginScreen(frame));
    }

    private static void showGeneratedSeed(JFrame parent) {
        List<String> generatedSeed = generateSeed();
        String seedString = String.join(" ", generatedSeed);

        // Save the generated seed to a file
        saveSeed(seedString);

        JTextArea seedTextArea = new JTextArea(seedString);
        seedTextArea.setEditable(false);
        seedTextArea.setLineWrap(true);
        seedTextArea.setWrapStyleWord(true);

        JScrollPane scrollPane = new JScrollPane(seedTextArea);
        scrollPane.setPreferredSize(new Dimension(300, 100));

        JOptionPane.showMessageDialog(parent, scrollPane,
                "Your seed words (copy them somewhere safe):", JOptionPane.INFORMATION_MESSAGE);
    }

    private static void showLoginScreen(JFrame parent) {
        JTextArea seedInput = new JTextArea(5, 20);
        JScrollPane scrollPane = new JScrollPane(seedInput);

        int result = JOptionPane.showConfirmDialog(parent, scrollPane,
                "Type your seed words (separated by spaces)", JOptionPane.OK_CANCEL_OPTION);

        if (result == JOptionPane.OK_OPTION) {
            String input = seedInput.getText().trim();
            List<String> inputWords = Arrays.asList(input.split("\\s+"));

            if (validateSeed(inputWords)) {
                JOptionPane.showMessageDialog(parent, "\u2713 Logged in successfully!", "Success", JOptionPane.INFORMATION_MESSAGE);
            } else {
                JOptionPane.showMessageDialog(parent, "\u274C Invalid User", "Error", JOptionPane.ERROR_MESSAGE);
            }
        }
    }

    private static List<String> generateSeed() {
        if (wordList.isEmpty()) {
            throw new IllegalStateException("Error 999, please contact support center");
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
            wordList = Collections.emptyList();
            System.err.println("Error loading words from file: " + e.getMessage());
        }
    }

    private static void saveSeed(String seed) {
        try (BufferedWriter writer = new BufferedWriter(new FileWriter(SEED_FILE, true))) {
            writer.write(seed);
            writer.newLine();
        } catch (IOException e) {
            System.err.println("Error saving seed: " + e.getMessage());
        }
    }

    private static boolean validateSeed(List<String> inputSeed) {
        try {
            List<String> lines = Files.readAllLines(Paths.get(SEED_FILE));
            for (String line : lines) {
                List<String> storedSeed = Arrays.asList(line.trim().split("\\s+"));
                if (storedSeed.equals(inputSeed)) {
                    return true;
                }
            }
            return false;
        } catch (IOException e) {
            System.err.println("Error reading seed file: " + e.getMessage());
            return false;
        }
    }
}