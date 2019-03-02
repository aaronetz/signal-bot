package com.woodencloset.signalbot.responders;

import com.woodencloset.signalbot.SignalBot;

import java.util.Random;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

public class DiceRollResponder implements SignalBot.Responder {
    private static final Pattern DICE_ROLL_PATTERN = Pattern.compile("(?i)roll\\s+(?<dice>\\d+)d(?<sides>\\d+)");
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

            String result = String.format("%dd%d: %s", numDice, numSides, randomString);
            return result;
        }
        return null;
    }
}
