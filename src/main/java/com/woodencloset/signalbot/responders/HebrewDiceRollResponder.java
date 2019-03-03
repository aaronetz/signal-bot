package com.woodencloset.signalbot.responders;

import com.woodencloset.signalbot.SignalBot;

import java.util.Random;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

public class HebrewDiceRollResponder implements SignalBot.Responder {
    private static final Pattern DICE_ROLL_PATTERN = Pattern.compile("(?<sides>\\d+)ק(?<dice>\\d+)\\s+לגלג");
    private static final Random RANDOM = new Random();
    private static final int MAX_DICE = 20;
    private static final int MAX_SIDES = 100;

    @Override
    public String getResponse(String messageText) {
        Matcher matcher = DICE_ROLL_PATTERN.matcher(messageText);
        if (matcher.matches()) {
            int numDice = Math.min(Integer.parseInt(matcher.group("dice")), MAX_DICE);
            int numSides = Math.min(Integer.parseInt(matcher.group("sides")), MAX_SIDES);
            String randomString = RANDOM.ints(numDice, 1, numSides + 1)
                    .mapToObj(String::valueOf)
                    .collect(Collectors.joining(", ", "[", "]"));

            return String.format("%s :%dק%d", randomString, numSides, numDice);
        }
        return null;
    }
}
