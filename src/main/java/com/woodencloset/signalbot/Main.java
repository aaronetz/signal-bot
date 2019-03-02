package com.woodencloset.signalbot;

import com.woodencloset.signalbot.responders.DiceRollResponder;
import org.apache.commons.cli.*;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.whispersystems.libsignal.InvalidKeyException;

import java.io.IOException;
import java.security.Security;
import java.util.prefs.BackingStoreException;

public class Main {

    static private SignalBot bot = new SignalBot();

    public static void main(String[] args) throws IOException, InvalidKeyException, BackingStoreException {

        Security.addProvider(new BouncyCastleProvider());

        Options options = new Options();
        OptionGroup commands = new OptionGroup();
        commands.setRequired(true);
        commands.addOption(new Option("r", "register", true, "Register user with given phone number. Sends a verification SMS."));
        commands.addOption(new Option("v", "verify", true, "Verify user with given verification code."));
        commands.addOption(new Option("l", "listen", false, "Listen to incoming messages"));
        options.addOptionGroup(commands);

        CommandLineParser parser = new DefaultParser();
        CommandLine cmd = null;
        try {
            cmd = parser.parse(options, args);
        } catch (ParseException e) {
            String header = "Signal bot service\n\n";
            String footer = "";
            HelpFormatter formatter = new HelpFormatter();
            formatter.printHelp("signal-bot", header, options, footer, true);
            System.exit(1);
        }

        if (cmd.hasOption("register")) {
            bot.register(cmd.getOptionValue("register"));
        } else if (cmd.hasOption("verify")) {
            bot.verify(cmd.getOptionValue("verify"));
        } else if (cmd.hasOption("listen")) {
            Runtime.getRuntime().addShutdownHook(new Thread(() -> bot.stopListening()));
            bot.addResponder(new DiceRollResponder());
            bot.listen();
        }
    }
}

