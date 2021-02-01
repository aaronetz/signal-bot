# signal-bot
This is a simple bot system for [Signal](https://github.com/signalapp) with minimal dependencies. Pure Java and cross platform.

## Prerequisites
- JDK 11+ due to TLS v3 requirement. A newer JDK version should work but it's untested. You can get an installer from [AdoptOpenJDK](https://adoptopenjdk.net/).
- A phone number you can receive SMS messages or voice calls on. You'll need to dedicate that number to the bot.

## Building
`gradlew installDist` should generate a run script at 'build/install/signal-bot/bin/signal-bot'.

## Running
1. To register the bot on the Signal service, run `signal-bot --register-text +12223334444` (change the phone number to any number that you can receive an SMS on.)
    * To get the verification code using a voice call instead, replace `register-text` with `register-voice`.
2. After receiving the verification SMS, run `signal-bot --verify 123-456` (change the number to the code you received.)
3. To start the bot, run `signal-bot --listen`. You should be able to then message the bot and see your messages in the log.
    * Note: it might take a few minutes for the bot to be properly registered with the Signal server and be able to receive messages.
4. To stop the bot, interrupt with Ctrl+C or `kill -2` to allow it to shut down and disconnect gracefully from the Signal service.
5. To dry-run test the listener, use `signal-bot --test`. This will start a simple input loop that sends your messages to the bot and sends the response to stdout. This doesn't use the Signal service.

## Adding new message responders
1. Create a new class that implements `SignalBot.Responder`. For example, this will echo back every message received:
```java
package com.woodencloset.signalbot.responders;

import com.woodencloset.signalbot.SignalBot;

public class EchoResponder implements SignalBot.Responder {
    @Override
    public String getResponse(String messageText) {
        return messageText;
    }
}
```
2. Add the line `bot.addResponder(new EchoResponder());` to the `Main` class (as an example, there is a `DiceRollResponder` included and added already.)

## Limitations
- For code simplicity, keys are stored in-memory, so it's mostly suitable for a long running session on a server. If you terminate and re-run, all keys (including identity key) will be re-generated which would necessitate other parties to re-approve the bot's identity.
- Group info is stored in-memory as well. If you join a group and then re-run the bot, the first message in the group will be ignored as the bot updates its internal group info. This could be solved by using a message queue, but that's currently not implemented, for code simplicity.
- Bot interface only supports receiving and sending simple text responses. No images or other data. Messages are always sent back to the sender, or to the group, if sent from one.
- Only legacy groups are currently supported. Supports for new groups is WIP.
