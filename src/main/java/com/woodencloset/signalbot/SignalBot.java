package com.woodencloset.signalbot;

import org.signal.libsignal.metadata.certificate.CertificateValidator;
import org.whispersystems.libsignal.IdentityKeyPair;
import org.whispersystems.libsignal.InvalidKeyException;
import org.whispersystems.libsignal.ecc.Curve;
import org.whispersystems.libsignal.state.PreKeyRecord;
import org.whispersystems.libsignal.state.SignalProtocolStore;
import org.whispersystems.libsignal.state.SignedPreKeyRecord;
import org.whispersystems.libsignal.state.impl.InMemorySignalProtocolStore;
import org.whispersystems.libsignal.util.KeyHelper;
import org.whispersystems.libsignal.util.Medium;
import org.whispersystems.libsignal.util.guava.Optional;
import org.whispersystems.signalservice.api.SignalServiceAccountManager;
import org.whispersystems.signalservice.api.SignalServiceMessagePipe;
import org.whispersystems.signalservice.api.SignalServiceMessageReceiver;
import org.whispersystems.signalservice.api.SignalServiceMessageSender;
import org.whispersystems.signalservice.api.crypto.SignalServiceCipher;
import org.whispersystems.signalservice.api.crypto.UnidentifiedAccess;
import org.whispersystems.signalservice.api.crypto.UnidentifiedAccessPair;
import org.whispersystems.signalservice.api.messages.SignalServiceContent;
import org.whispersystems.signalservice.api.messages.SignalServiceDataMessage;
import org.whispersystems.signalservice.api.messages.SignalServiceEnvelope;
import org.whispersystems.signalservice.api.messages.SignalServiceGroup;
import org.whispersystems.signalservice.api.push.SignalServiceAddress;
import org.whispersystems.signalservice.api.push.TrustStore;
import org.whispersystems.signalservice.api.util.UptimeSleepTimer;
import org.whispersystems.signalservice.api.websocket.ConnectivityListener;
import org.whispersystems.signalservice.internal.configuration.SignalCdnUrl;
import org.whispersystems.signalservice.internal.configuration.SignalContactDiscoveryUrl;
import org.whispersystems.signalservice.internal.configuration.SignalServiceConfiguration;
import org.whispersystems.signalservice.internal.configuration.SignalServiceUrl;
import org.whispersystems.util.Base64;
import org.whispersystems.signalservice.internal.util.Util;

import java.io.IOException;
import java.io.InputStream;
import java.security.SecureRandom;
import java.util.*;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.logging.Logger;
import java.util.prefs.BackingStoreException;
import java.util.prefs.Preferences;

public class SignalBot {
    public enum RegistrationType {
        TextMessage,
        PhoneCall
    }

    private static final String UNIDENTIFIED_SENDER_TRUST_ROOT = "BXu6QIKVz5MA8gstzfOgRQGqyLqOwNKHL6INkv3IHWMF";
    private static final String SIGNAL_URL = "https://textsecure-service.whispersystems.org";
    private static final String SIGNAL_CDN_URL = "https://cdn.signal.org";
    private static final String SIGNAL_CONTACT_DISCOVERY_URL = "https://api.directory.signal.org";
    private static final String USER_AGENT = "BOT";
    public static final String SIGNAL_CAPTCHA_URL = "https://signalcaptchas.org/registration/generate.html";
    private static final String SIGNAL_CAPTCHA_SCHEME = "signalcaptcha://";
    private static final TrustStore TRUST_STORE = new TrustStore() {
        @Override
        public InputStream getKeyStoreInputStream() {
            return getClass().getResourceAsStream("/whisper.store");
        }

        @Override
        public String getKeyStorePassword() {
            return "whisper";
        }
    };
    private static final int BATCH_SIZE = 100;
    private static Logger logger = Logger.getLogger(SignalBot.class.getSimpleName());
    private static Preferences prefs = Preferences.userNodeForPackage(SignalBot.class).node(SignalBot.class.getSimpleName());
    private static SignalServiceConfiguration config = new SignalServiceConfiguration(
            new SignalServiceUrl[]{new SignalServiceUrl(SIGNAL_URL, TRUST_STORE)},
            new SignalCdnUrl[]{new SignalCdnUrl(SIGNAL_CDN_URL, TRUST_STORE)},
            new SignalContactDiscoveryUrl[]{new SignalContactDiscoveryUrl(SIGNAL_CONTACT_DISCOVERY_URL, TRUST_STORE)});
    private Thread messageRetrieverThread = new Thread(new MessageRetriever());
    private SignalProtocolStore protocolStore;
    private Map<String, List<SignalServiceAddress>> groupIdToMembers = new HashMap<>();
    private List<Responder> responders = new LinkedList<>();
    private SignalServiceAccountManager accountManager;
    
    public void register(String username, RegistrationType type, String captcha) throws IOException, BackingStoreException {
        logger.info("Sending verification code to " + username + ".");
        prefs.clear();
        String password = Base64.encodeBytes(Util.getSecretBytes(18));
        prefs.put("LOCAL_USERNAME", username);
        prefs.put("LOCAL_PASSWORD", password);
        accountManager = new SignalServiceAccountManager(config, null, username, password, USER_AGENT);
        if (captcha != null && captcha.length() > 0) {
            if (captcha.startsWith(SIGNAL_CAPTCHA_SCHEME)) {
                captcha = captcha.substring(SIGNAL_CAPTCHA_SCHEME.length());
                logger.info("Using captcha token " + captcha);
            } else {
                logger.warning("Unknown captcha response supplied, please use raw response from " + SIGNAL_CAPTCHA_URL + ", including the following prefix: " + SIGNAL_CAPTCHA_SCHEME);
            }
        }
        if (type == RegistrationType.PhoneCall) {
            accountManager.requestVoiceVerificationCode(Locale.getDefault(), Optional.fromNullable(captcha), Optional.absent());
        } else {
            accountManager.requestSmsVerificationCode(false, Optional.fromNullable(captcha), Optional.absent());
        }
    }

    public void verify(String verificationCode) throws IOException {
        String username = prefs.get("LOCAL_USERNAME", null);
        String password = prefs.get("LOCAL_PASSWORD", null);
        logger.info("Verifying user " + username + " with code " + verificationCode + "...");
        String code = verificationCode.replace("-", "");
        int registrationId = KeyHelper.generateRegistrationId(false);
        prefs.putInt("REGISTRATION_ID", registrationId);
        byte[] profileKey = Util.getSecretBytes(32);
        byte[] unidentifiedAccessKey = UnidentifiedAccess.deriveAccessKeyFrom(profileKey);
        accountManager = new SignalServiceAccountManager(config, null, username, password, USER_AGENT);
        UUID uuid = accountManager.verifyAccountWithCode(code, null, registrationId, true, null, unidentifiedAccessKey, false);
        prefs.put("UUID", uuid.toString());
    }

    public void listen() throws IOException, InvalidKeyException {
        String username = prefs.get("LOCAL_USERNAME", null);
        String password = prefs.get("LOCAL_PASSWORD", null);
        int registrationId = prefs.getInt("REGISTRATION_ID", -1);
        UUID uuid = UUID.fromString(prefs.get("UUID", ""));
        logger.info("Generating keys for " + username + "...");
        IdentityKeyPair identityKeyPair = KeyHelper.generateIdentityKeyPair();
        this.protocolStore = new InMemorySignalProtocolStore(identityKeyPair, registrationId);
        accountManager = new SignalServiceAccountManager(config, uuid, username, password, USER_AGENT);
        refreshPreKeys(identityKeyPair);
        logger.info("Starting message listener...");
        messageRetrieverThread.start();
        // TODO refresh keys job
    }

    public void stopListening() {
        if (!messageRetrieverThread.isAlive()) return;
        logger.info("Stopping message listener...");
        messageRetrieverThread.interrupt();
        try {
            messageRetrieverThread.join();
        } catch (InterruptedException e) {
            logger.warning(e.toString());
        }
        logger.info("Message listener stopped.");
    }

    public void testResponders(String input) {
        logger.info("Testing responders on input: " + input);
        for (Responder responder : responders) {
            String response = responder.getResponse(input);
            logger.info(responder.getClass().getSimpleName() + " sending response: " + response);
        }
    }

    public void addResponder(Responder responder) {
        responders.add(responder);
    }

    private void refreshPreKeys(IdentityKeyPair identityKeyPair) throws IOException, InvalidKeyException {
        int initialPreKeyId = new SecureRandom().nextInt(Medium.MAX_VALUE);
        List<PreKeyRecord> records = KeyHelper.generatePreKeys(initialPreKeyId, BATCH_SIZE);
        records.forEach((v) -> this.protocolStore.storePreKey(v.getId(), v));
        int signedPreKeyId = new SecureRandom().nextInt(Medium.MAX_VALUE);
        SignedPreKeyRecord signedPreKey = KeyHelper.generateSignedPreKey(identityKeyPair, signedPreKeyId);
        this.protocolStore.storeSignedPreKey(signedPreKey.getId(), signedPreKey);
        this.accountManager.setPreKeys(identityKeyPair.getPublicKey(), signedPreKey, records);
    }

    public interface Responder {
        /**
         * @param messageText input message
         * @return message to send back, or null for no response
         */
        String getResponse(String messageText);
    }

    private class MessageRetriever implements Runnable {

        @Override
        public void run() {
            String username = prefs.get("LOCAL_USERNAME", null);
            String password = prefs.get("LOCAL_PASSWORD", null);
            UUID uuid = UUID.fromString(prefs.get("UUID", ""));
            SignalServiceMessageReceiver messageReceiver = new SignalServiceMessageReceiver(config, uuid,
                    username, password, null, USER_AGENT,
                    new PipeConnectivityListener(), new UptimeSleepTimer());
            SignalServiceMessageSender messageSender = new SignalServiceMessageSender(config, uuid, username, password, protocolStore, USER_AGENT,
                    false, Optional.absent(), Optional.absent(), Optional.absent());
            CertificateValidator validator;
            try {
                validator = new CertificateValidator(Curve.decodePoint(Base64.decode(UNIDENTIFIED_SENDER_TRUST_ROOT), 0));
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
            SignalServiceCipher cipher = new SignalServiceCipher(new SignalServiceAddress(uuid, username), protocolStore, validator);
            SignalServiceMessagePipe messagePipe = messageReceiver.createMessagePipe();
            try {
                while (!Thread.currentThread().isInterrupted()) {
                    try {
                        logger.info("Waiting for messages...");
                        SignalServiceEnvelope envelope = messagePipe.read(60, TimeUnit.SECONDS);
                        if (envelope.isPreKeySignalMessage()) {
                            logger.info("Pre keys count: " + accountManager.getPreKeysCount());
                        }
                        SignalServiceContent message = cipher.decrypt(envelope);
                        if (message == null) continue;
                        SignalServiceAddress sender = message.getSender();
                        SignalServiceDataMessage messageData = message.getDataMessage().orNull();
                        if (messageData == null) continue;
                        SignalServiceGroup groupInfo = messageData.getGroupInfo().orNull();
                        byte[] groupId = {};
                        String groupIdKey = "";
                        if (groupInfo != null) {
                            groupId = groupInfo.getGroupId();
                            groupIdKey = new String(groupId);
                            if (groupInfo.getMembers().isPresent()) {
                                logger.info("Received member list for group: " + groupInfo.getName().or("n/a"));
                                groupIdToMembers.put(groupIdKey, groupInfo.getMembers().get());
                            } else if (!groupIdToMembers.containsKey(groupIdKey)) {
                                logger.info("Received message from an unknown group, sending info request.");
                                SignalServiceGroup group = SignalServiceGroup.newBuilder(SignalServiceGroup.Type.REQUEST_INFO).withId(groupId).build();
                                SignalServiceDataMessage groupInfoRequestMessage = SignalServiceDataMessage.newBuilder().asGroupMessage(group).build();
                                messageSender.sendMessage(sender, Optional.absent(), groupInfoRequestMessage);
                                continue;
                            }
                        }
                        String messageBody = messageData.getBody().or("");
                        if (!messageBody.isEmpty()) {
                            logger.info("Received message: " + messageBody);
                            for (Responder responder : responders) {
                                String response = responder.getResponse(messageBody);
                                if (response != null && !response.isEmpty()) {
                                    logger.info(responder.getClass().getSimpleName() + " sending response: " + response);
                                    long quoteId = messageData.getTimestamp();
                                    SignalServiceDataMessage.Quote quote = new SignalServiceDataMessage.Quote(quoteId, sender, messageBody, new LinkedList<>());
                                    if (groupInfo != null) {
                                        List<SignalServiceAddress> groupMembers = groupIdToMembers.get(groupIdKey);
                                        List<Optional<UnidentifiedAccessPair>> uap = Collections.nCopies(groupMembers.size(), Optional.absent());
                                        SignalServiceGroup group = SignalServiceGroup.newBuilder(SignalServiceGroup.Type.DELIVER).withId(groupId).build();
                                        SignalServiceDataMessage responseData = SignalServiceDataMessage.newBuilder().asGroupMessage(group).withQuote(quote).withBody(response).build();
                                        messageSender.sendMessage(groupMembers, uap, false, responseData);
                                    } else {
                                        SignalServiceDataMessage responseData = SignalServiceDataMessage.newBuilder().withQuote(quote).withBody(response).build();
                                        messageSender.sendMessage(sender, Optional.absent(), responseData);
                                    }
                                }
                            }
                        }
                    } catch (TimeoutException e) {
                        // Just let it run again
                    } catch (Exception e) {
                        logger.warning("Error processing message: " + e);
                    }
                }
            } catch (Throwable t) {
                // avoiding the AssertionError coming from messagePipe.read when it's interrupted...
            } finally {
                logger.info("Shutting down message pipe...");
                messagePipe.shutdown();
            }
        }
    }

    private static class PipeConnectivityListener implements ConnectivityListener {

        @Override
        public void onConnected() {
            logger.info("Message pipe connected.");
        }

        @Override
        public void onConnecting() {
            logger.info("Message pipe connecting...");
        }

        @Override
        public void onDisconnected() {
            logger.info("Message pipe disconnected.");
        }

        @Override
        public void onAuthenticationFailure() {
            logger.info("Message pipe failure!");
        }
    }
}
