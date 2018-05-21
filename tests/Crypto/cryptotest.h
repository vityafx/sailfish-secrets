/*
 * Copyright (C) 2017 Jolla Ltd.
 * Contact: Bea Lam <bea.lam@jollamobile.com>
 * All rights reserved.
 * BSD 3-Clause License, see LICENSE.
 */

#ifndef SAILFISHSECRETS_CRYPTOTEST_H
#define SAILFISHSECRETS_CRYPTOTEST_H

#include "Crypto/cryptomanager.h"
#include "Crypto/cryptomanager_p.h"
#include "Crypto/serialization_p.h"
#include "Crypto/key.h"
#include "Crypto/result.h"

#include "Secrets/secretmanager.h"
#include "Secrets/secretmanager_p.h"
#include "Secrets/serialization_p.h"
#include "Secrets/result.h"

#include <QtTest>
#include <QDBusReply>
#include <QVariantMap>
#include <QFile>

#define DEFAULT_TEST_CRYPTO_PLUGIN_NAME CryptoManager::DefaultCryptoPluginName + QLatin1String(".test")
#define DEFAULT_PLUGIN_CRYPTO_STORAGE CryptoManager::DefaultCryptoStoragePluginName + QLatin1String(".test")
#define DEFAULT_TEST_STORAGE_PLUGIN Sailfish::Secrets::SecretManager::DefaultStoragePluginName + QLatin1String(".test")
#define DEFAULT_TEST_CRYPTO_STORAGE_PLUGIN_NAME Sailfish::Secrets::SecretManager::DefaultEncryptedStoragePluginName + QLatin1String(".test")
#define PASSWORD_AGENT_TEST_AUTH_PLUGIN Sailfish::Secrets::SecretManager::DefaultAuthenticationPluginName + QLatin1String(".test")
#define IN_APP_TEST_AUTHENTICATION_PLUGIN Sailfish::Secrets::SecretManager::InAppAuthenticationPluginName + QLatin1String(".test")
#define DEFAULT_TEST_ENCRYPTION_PLUGIN Sailfish::Secrets::SecretManager::DefaultEncryptionPluginName + QLatin1String(".test")
#define TEST_USB_TOKEN_PLUGIN_NAME QStringLiteral("org.sailfishos.secrets.plugin.cryptostorage.exampleusbtoken.test")

#define WAIT_FOR_DBUS_REPLY(reply) \
    QTRY_VERIFY_WITH_TIMEOUT(reply.isFinished(), 10 * 1000);

#define WAIT_FOR_DBUS_REPLY_SUCCEEDED(reply) \
    WAIT_FOR_DBUS_REPLY(reply); \
    QVERIFY(reply.isValid()); \
    if (reply.argumentAt<0>().code() != (int)Sailfish::Crypto::Result::Succeeded) { \
        qWarning() << "Request failed:" << reply.argumentAt<0>().errorMessage(); \
    } \
    QCOMPARE((int)reply.argumentAt<0>().code(), (int)Sailfish::Crypto::Result::Succeeded); \
    QCOMPARE(reply.argumentAt<0>().errorMessage(), QString());

#define WAIT_FOR_DBUS_REPLY_FAILED(reply) \
    WAIT_FOR_DBUS_REPLY(reply); \
    QVERIFY(reply.isValid()); \
    QCOMPARE((int)reply.argumentAt<0>().code(), (int)Sailfish::Crypto::Result::Failed);

#define WAIT_FOR_REQUEST_WITH_TIMEOUT(request, timeout) \
    QTRY_COMPARE_WITH_TIMEOUT((int)request.status(), (int)Sailfish::Crypto::Request::Finished, timeout); \
    QCOMPARE((int)request.status(), (int)Sailfish::Crypto::Request::Finished);

#define WAIT_FOR_REQUEST_SUCCEEDED_WITH_TIMEOUT(request, timeout) \
    QCOMPARE((int)request.status(), (int)Sailfish::Crypto::Request::Active); \
    QCOMPARE((int)request.result().code(), (int)Sailfish::Crypto::Result::Pending); \
    QCOMPARE(request.result().errorMessage(), QString()); \
    WAIT_FOR_REQUEST_WITH_TIMEOUT(request, timeout); \
    if ((int)request.result().code() != (int)Sailfish::Crypto::Result::Succeeded) { \
        qWarning() << "Request failed:" << request.result().errorMessage(); \
    } else if (!request.result().errorMessage().isEmpty()) { \
        qWarning() << "Request succeeded by has non-empty error message:" << request.result().errorMessage(); \
    } \
    QCOMPARE((int)request.result().code(), (int)Sailfish::Crypto::Result::Succeeded); \
    QCOMPARE(request.result().errorMessage(), QString()); \

#define WAIT_FOR_REQUEST_SUCCEEDED(request) \
    WAIT_FOR_REQUEST_SUCCEEDED_WITH_TIMEOUT(request, 10 * 1000)

#define WAIT_LONG_FOR_REQUEST_SUCCEEDED(request) \
    WAIT_FOR_REQUEST_SUCCEEDED_WITH_TIMEOUT(request, 60 * 1000)

#define WAIT_FOR_REQUEST_FAILED(request) \
    WAIT_FOR_REQUEST_WITH_TIMEOUT(request, 10 * 1000); \
    QCOMPARE((int)request.result().code(), (int)Sailfish::Crypto::Result::Failed);

#define WAIT_FOR_REQUEST(request) \
    WAIT_FOR_REQUEST_WITH_TIMEOUT(request, 10 * 1000)


// Defines the QFETCH() calls for the test data added by addCryptoTestData().
#define FETCH_CRYPTO_TEST_DATA \
    QFETCH(TestPluginMap, plugins); \
    QFETCH(CryptoManager::BlockMode, blockMode); \
    QFETCH(CryptoManager::EncryptionPadding, padding); \
    QFETCH(Key, keyTemplate); \
    QFETCH(QByteArray, authData); \
    QFETCH(QByteArray, plaintext); \
    QFETCH(QByteArray, initVector); \


class TestCryptoManager : public Sailfish::Crypto::CryptoManager
{
    Q_OBJECT

public:
    TestCryptoManager(QObject *parent = Q_NULLPTR)
        : Sailfish::Crypto::CryptoManager(parent) {}
    ~TestCryptoManager() {}
    Sailfish::Crypto::CryptoManagerPrivate *priv() const { return Sailfish::Crypto::CryptoManager::pimpl(); }
};


class TestSecretManager : public Sailfish::Secrets::SecretManager
{
    Q_OBJECT

public:
    TestSecretManager(QObject *parent = Q_NULLPTR)
        : Sailfish::Secrets::SecretManager(parent) {}
    ~TestSecretManager() {}
    Sailfish::Secrets::SecretManagerPrivate *priv() const { return Sailfish::Secrets::SecretManager::pimpl(); }
};

class CryptoTest : public QObject
{
    Q_OBJECT

public:
    enum AuthenticationMode {
        NoAuthentication,
        Authentication
    };
    Q_ENUM(AuthenticationMode)

    enum PluginType {
        CryptoPlugin,
        StoragePlugin,
        AuthenticationPlugin,
        InAppAuthenticationPlugin,
        EncryptionPlugin
    };
    Q_ENUM(PluginType)

    typedef QMap<PluginType, QString> TestPluginMap;

    explicit CryptoTest(QObject *parent = nullptr);

    void qtest_init();
    void qtest_cleanup();

    QByteArray createRandomTestData(int size);
    QByteArray generateInitializationVector(Sailfish::Crypto::CryptoManager::Algorithm algorithm,
                                            Sailfish::Crypto::CryptoManager::BlockMode blockMode);
    QByteArray generateRsaPlaintext(Sailfish::Crypto::CryptoManager::EncryptionPadding padding, int keySize);

    bool allCharactersAreNull(const QString &s);

    // Creates Key with filter of test=true, plus the given parameters.
    Sailfish::Crypto::Key createTestKey(int keySize,
                                        Sailfish::Crypto::CryptoManager::Algorithm algorithm,
                                        Sailfish::Crypto::Key::Origin origins,
                                        Sailfish::Crypto::CryptoManager::Operations operations,
                                        Sailfish::Crypto::Key::Identifier keyIdentifier = Sailfish::Crypto::Key::Identifier());

    void addCryptoTestData(const TestPluginMap &plugins,
                           Sailfish::Crypto::Key::Origin keyOrigin,
                           Sailfish::Crypto::CryptoManager::Operations operations,
                           Sailfish::Crypto::Key::Identifier keyIdentifier = Sailfish::Crypto::Key::Identifier(),
                           const QByteArray &plaintext = QByteArray());

    QFile *m_devRandom;

    TestCryptoManager m_cm;
    Sailfish::Crypto::CryptoManagerPrivate &m_cmp = *(m_cm.priv());

    TestSecretManager m_sm;
    Sailfish::Secrets::SecretManagerPrivate &m_smp = *(m_sm.priv());

    struct TestCollection {
        QString name;
        QString storagePlugin;
        Sailfish::Secrets::SecretManager::UserInteractionMode userInteractionMode;
    };
    QList<TestCollection> m_populatedCollections;
};

Q_DECLARE_METATYPE(Sailfish::Crypto::Result::ResultCode)
Q_DECLARE_METATYPE(Sailfish::Crypto::Result::ErrorCode)
Q_DECLARE_METATYPE(CryptoTest::AuthenticationMode)
Q_DECLARE_METATYPE(CryptoTest::PluginType)
Q_DECLARE_METATYPE(CryptoTest::TestPluginMap)

#endif  // SAILFISHSECRETS_CRYPTOTEST_H
