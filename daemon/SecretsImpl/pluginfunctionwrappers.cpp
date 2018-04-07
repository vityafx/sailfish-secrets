/*
 * Copyright (C) 2018 Jolla Ltd.
 * Contact: Chris Adams <chris.adams@jollamobile.com>
 * All rights reserved.
 * BSD 3-Clause License, see LICENSE.
 */

#include "pluginfunctionwrappers_p.h"
#include "logging_p.h"

using namespace Sailfish::Secrets;
using namespace Sailfish::Secrets::Daemon::ApiImpl;

/* These methods are to be called via QtConcurrent */

FoundResult Daemon::ApiImpl::lockSpecificPlugin(
        const QMap<QString, StoragePlugin*> &storagePlugins,
        const QMap<QString, EncryptionPlugin*> &encryptionPlugins,
        const QMap<QString, EncryptedStoragePlugin*> &encryptedStoragePlugins,
        const QString &lockCodeTarget)
{
    auto lambda = [] (PluginBase *p,
                      const QString &type,
                      const QString &name,
                      Result *result) {
        if (!p->supportsLocking()) {
            *result = Result(Result::OperationNotSupportedError,
                             QStringLiteral("%1 plugin %2 does not support locking")
                             .arg(type, name));
        }
        if (p->isLocked() && !p->lock()) {
            *result = Result(Result::UnknownError,
                             QStringLiteral("Failed to lock %1 plugin %2")
                             .arg(type, name));
        }
    };

    bool found = true;
    Result result(Result::Succeeded);
    if (storagePlugins.contains(lockCodeTarget)) {
        lambda(storagePlugins.value(lockCodeTarget),
               QStringLiteral("storage"),
               lockCodeTarget,
               &result);
    } else if (encryptedStoragePlugins.contains(lockCodeTarget)) {
        lambda(encryptedStoragePlugins.value(lockCodeTarget),
               QStringLiteral("encrypted storage"),
               lockCodeTarget,
               &result);
    } else if (encryptionPlugins.contains(lockCodeTarget)) {
        lambda(encryptionPlugins.value(lockCodeTarget),
               QStringLiteral("encryption"),
               lockCodeTarget,
               &result);
    } else {
        found = false;
    }

    return FoundResult(found, result);
}

FoundResult Daemon::ApiImpl::unlockSpecificPlugin(
        const QMap<QString, StoragePlugin*> &storagePlugins,
        const QMap<QString, EncryptionPlugin*> &encryptionPlugins,
        const QMap<QString, EncryptedStoragePlugin*> &encryptedStoragePlugins,
        const QString &lockCodeTarget,
        const QByteArray &lockCode)
{
    auto lambda = [] (PluginBase *p,
                      const QString &type,
                      const QString &name,
                      const QByteArray &lockCode,
                      Result *result) {
        if (!p->supportsLocking()) {
            *result = Result(Result::OperationNotSupportedError,
                             QStringLiteral("%1 plugin %2 does not support locking")
                             .arg(type, name));
        }
        if (!p->isLocked() && !p->unlock(lockCode)) {
            *result = Result(Result::UnknownError,
                             QStringLiteral("Failed to unlock %1 plugin %2")
                             .arg(type, name));
        }
    };

    bool found = true;
    Result result(Result::Succeeded);
    if (storagePlugins.contains(lockCodeTarget)) {
        lambda(storagePlugins.value(lockCodeTarget),
               QStringLiteral("storage"),
               lockCodeTarget,
               lockCode,
               &result);
    } else if (encryptedStoragePlugins.contains(lockCodeTarget)) {
        lambda(encryptedStoragePlugins.value(lockCodeTarget),
               QStringLiteral("encrypted storage"),
               lockCodeTarget,
               lockCode,
               &result);
    } else if (encryptionPlugins.contains(lockCodeTarget)) {
        lambda(encryptionPlugins.value(lockCodeTarget),
               QStringLiteral("encryption"),
               lockCodeTarget,
               lockCode,
               &result);
    } else {
        found = false;
    }

    return FoundResult(found, result);
}

FoundResult Daemon::ApiImpl::modifyLockSpecificPlugin(
        const QMap<QString, StoragePlugin*> &storagePlugins,
        const QMap<QString, EncryptionPlugin*> &encryptionPlugins,
        const QMap<QString, EncryptedStoragePlugin*> &encryptedStoragePlugins,
        const QString &lockCodeTarget,
        const LockCodes &newAndOldLockCode)
{
    auto lambda = [] (PluginBase *p,
                      const QString &type,
                      const QString &name,
                      const QByteArray &oldLockCode,
                      const QByteArray &newLockCode,
                      Result *result) {
        if (!p->supportsLocking()) {
            *result = Result(Result::OperationNotSupportedError,
                             QStringLiteral("%1 plugin %2 does not support locking")
                             .arg(type, name));
        }
        if (!p->setLockCode(oldLockCode, newLockCode)) {
            *result = Result(Result::UnknownError,
                             QStringLiteral("Failed to set lock code for %1 plugin %2")
                             .arg(type, name));
        }
    };

    bool found = true;
    Result result(Result::Succeeded);
    if (storagePlugins.contains(lockCodeTarget)) {
        lambda(storagePlugins.value(lockCodeTarget),
               QStringLiteral("storage"),
               lockCodeTarget,
               newAndOldLockCode.oldCode,
               newAndOldLockCode.newCode,
               &result);
    } else if (encryptedStoragePlugins.contains(lockCodeTarget)) {
        lambda(encryptedStoragePlugins.value(lockCodeTarget),
               QStringLiteral("encrypted storage"),
               lockCodeTarget,
               newAndOldLockCode.oldCode,
               newAndOldLockCode.newCode,
               &result);
    } else if (encryptionPlugins.contains(lockCodeTarget)) {
        lambda(encryptionPlugins.value(lockCodeTarget),
               QStringLiteral("encryption"),
               lockCodeTarget,
               newAndOldLockCode.oldCode,
               newAndOldLockCode.newCode,
               &result);
    } else {
        found = false;
    }

    return FoundResult(found, result);
}

bool Daemon::ApiImpl::masterLockPlugins(
        const QList<StoragePlugin*> &storagePlugins,
        const QList<EncryptedStoragePlugin*> &encryptedStoragePlugins)
{
    bool allSucceeded = true;
    for (StoragePlugin *splugin : storagePlugins) {
        if (splugin->supportsMasterLock()) {
            if (!splugin->isMasterLocked()) {
                if (!splugin->masterLock()) {
                    qCWarning(lcSailfishSecretsDaemon) << "Failed to master-lock storage plugin:" << splugin->name();
                    allSucceeded = false;
                }
            }
        }
    }
    for (EncryptedStoragePlugin *esplugin : encryptedStoragePlugins) {
        if (esplugin->supportsMasterLock()) {
            if (!esplugin->isMasterLocked()) {
                if (!esplugin->masterLock()) {
                    qCWarning(lcSailfishSecretsDaemon) << "Failed to master-lock encrypted storage plugin:" << esplugin->name();
                    allSucceeded = false;
                }
            }
        }
    }
    return allSucceeded;
}

bool Daemon::ApiImpl::masterUnlockPlugins(
        const QList<StoragePlugin*> &storagePlugins,
        const QList<EncryptedStoragePlugin*> &encryptedStoragePlugins,
        const QByteArray &encryptionKey)
{
    bool allSucceeded = true;
    for (StoragePlugin *splugin : storagePlugins) {
        if (splugin->supportsMasterLock()) {
            if (splugin->isMasterLocked()) {
                if (!splugin->masterUnlock(encryptionKey)) {
                    qCWarning(lcSailfishSecretsDaemon) << "Failed to master-unlock storage plugin:" << splugin->name();
                    allSucceeded = false;
                }
            }
        }
    }
    for (EncryptedStoragePlugin *esplugin : encryptedStoragePlugins) {
        if (esplugin->supportsMasterLock()) {
            if (esplugin->isMasterLocked()) {
                if (!esplugin->masterUnlock(encryptionKey)) {
                    qCWarning(lcSailfishSecretsDaemon) << "Failed to master-unlock encrypted storage plugin:" << esplugin->name();
                    allSucceeded = false;
                }
            }
        }
    }
    return allSucceeded;
}

bool Daemon::ApiImpl::modifyMasterLockPlugins(
        const QList<StoragePlugin*> &storagePlugins,
        const QList<EncryptedStoragePlugin*> &encryptedStoragePlugins,
        const QByteArray &oldEncryptionKey,
        const QByteArray &newEncryptionKey)
{
    bool allSucceeded = true;
    for (StoragePlugin *splugin : storagePlugins) {
        if (splugin->supportsMasterLock()) {
            if (splugin->isMasterLocked()) {
                if (!splugin->masterUnlock(oldEncryptionKey)) {
                    qCWarning(lcSailfishSecretsDaemon) << "Failed to master-unlock storage plugin:" << splugin->name();
                }
            }
            if (!splugin->setMasterLockKey(oldEncryptionKey, newEncryptionKey)) {
                qCWarning(lcSailfishSecretsDaemon) << "Failed to set master lock code for storage plugin:" << splugin->name();
                allSucceeded = false;
            }
        }
    }
    for (EncryptedStoragePlugin *esplugin : encryptedStoragePlugins) {
        if (esplugin->supportsMasterLock()) {
            if (esplugin->isMasterLocked()) {
                if (!esplugin->masterUnlock(oldEncryptionKey)) {
                    qCWarning(lcSailfishSecretsDaemon) << "Failed to master-unlock encrypted storage plugin:" << esplugin->name();
                }
            }
            if (!esplugin->setMasterLockKey(oldEncryptionKey, newEncryptionKey)) {
                qCWarning(lcSailfishSecretsDaemon) << "Failed to set master lock code for encrypted storage plugin:" << esplugin->name();
                allSucceeded = false;
            }
        }
    }
    return allSucceeded;
}

bool EncryptionPluginWrapper::isLocked(EncryptionPlugin *plugin)
{
    return plugin->isLocked();
}

bool EncryptionPluginWrapper::lock(EncryptionPlugin *plugin)
{
    return plugin->lock();
}

bool EncryptionPluginWrapper::unlock(EncryptionPlugin *plugin,
                                     const QByteArray &lockCode)
{
    return plugin->unlock(lockCode);
}

bool setLockCode(EncryptionPlugin *plugin,
                 const QByteArray &oldLockCode,
                 const QByteArray &newLockCode)
{
    return plugin->setLockCode(oldLockCode, newLockCode);
}

DerivedKeyResult
EncryptionPluginWrapper::deriveKeyFromCode(
        EncryptionPlugin *plugin,
        const QByteArray &authenticationCode,
        const QByteArray &salt)
{
    QByteArray key;
    Result result = plugin->deriveKeyFromCode(authenticationCode, salt, &key);
    return DerivedKeyResult(result, key);
}

EncryptionPluginWrapper::DataResult
EncryptionPluginWrapper::encryptSecret(
        EncryptionPlugin *plugin,
        const QByteArray &plaintext,
        const QByteArray &key)
{
    QByteArray ciphertext;
    Result result = plugin->encryptSecret(plaintext, key, &ciphertext);
    return EncryptionPluginWrapper::DataResult(result, ciphertext);
}

EncryptionPluginWrapper::DataResult
EncryptionPluginWrapper::decryptSecret(
        EncryptionPlugin *plugin,
        const QByteArray &encrypted,
        const QByteArray &key)
{
    QByteArray plaintext;
    Result result = plugin->decryptSecret(encrypted, key, &plaintext);
    return EncryptionPluginWrapper::DataResult(result, plaintext);
}

bool StoragePluginWrapper::isLocked(StoragePlugin *plugin)
{
    return plugin->isLocked();
}

bool StoragePluginWrapper::lock(StoragePlugin *plugin)
{
    return plugin->lock();
}

bool StoragePluginWrapper::unlock(
        StoragePlugin *plugin,
        const QByteArray &lockCode)
{
    return plugin->unlock(lockCode);
}

bool StoragePluginWrapper::setLockCode(
        StoragePlugin *plugin,
        const QByteArray &oldLockCode,
        const QByteArray &newLockCode)
{
    return plugin->setLockCode(oldLockCode, newLockCode);
}

Result StoragePluginWrapper::createCollection(
        StoragePlugin *plugin,
        const QString &collectionName)
{
    return plugin->createCollection(collectionName);
}

Result StoragePluginWrapper::removeCollection(
        StoragePlugin *plugin,
        const QString &collectionName)
{
    return plugin->removeCollection(collectionName);
}

Result StoragePluginWrapper::setSecret(
        StoragePlugin *plugin,
        const QString &collectionName,
        const QString &hashedSecretName,
        const QByteArray &encryptedSecretName,
        const QByteArray &secret,
        const Secret::FilterData &filterData)
{
    return plugin->setSecret(collectionName,
                             hashedSecretName,
                             encryptedSecretName,
                             secret,
                             filterData);
}

StoragePluginWrapper::SecretDataResult
StoragePluginWrapper::getSecret(
        StoragePlugin *plugin,
        const QString &collectionName,
        const QString &hashedSecretName)
{
    QByteArray encryptedSecretName;
    QByteArray secret;
    Secret::FilterData filterData;
    Result result = plugin->getSecret(collectionName,
                                      hashedSecretName,
                                      &encryptedSecretName,
                                      &secret,
                                      &filterData);
    return StoragePluginWrapper::SecretDataResult(
                result, encryptedSecretName, secret, filterData);
}

StoragePluginWrapper::EncryptedSecretNamesResult
StoragePluginWrapper::findSecrets(
        StoragePlugin *plugin,
        const QString &collectionName,
        const Secret::FilterData &filter,
        StoragePlugin::FilterOperator filterOperator)
{
    QVector<QByteArray> encryptedSecretNames;
    Result result = plugin->findSecrets(collectionName,
                                        filter,
                                        filterOperator,
                                        &encryptedSecretNames);
    return StoragePluginWrapper::EncryptedSecretNamesResult(
                result, encryptedSecretNames);
}

Result StoragePluginWrapper::removeSecret(
        StoragePlugin *plugin,
        const QString &collectionName,
        const QString &hashedSecretName)
{
    return plugin->removeSecret(collectionName,
                                hashedSecretName);
}

Result StoragePluginWrapper::reencryptSecrets(
        StoragePlugin *plugin,
        const QString &collectionName,
        const QVector<QString> &hashedSecretNames,
        const QByteArray &oldkey,
        const QByteArray &newkey,
        EncryptionPlugin *encryptionPlugin)
{
    return plugin->reencryptSecrets(collectionName,
                                    hashedSecretNames,
                                    oldkey,
                                    newkey,
                                    encryptionPlugin);
}

Result StoragePluginWrapper::encryptAndStoreSecret(
        EncryptionPlugin *encryptionPlugin,
        StoragePlugin *storagePlugin,
        const Secret &secret,
        const QString &hashedSecretName,
        const QByteArray &encryptionKey)
{
    QByteArray encrypted, encryptedName;
    Result pluginResult = encryptionPlugin->encryptSecret(secret.data(), encryptionKey, &encrypted);
    if (pluginResult.code() == Result::Succeeded) {
        pluginResult = encryptionPlugin->encryptSecret(secret.identifier().name().toUtf8(), encryptionKey, &encryptedName);
        if (pluginResult.code() == Result::Succeeded) {
            pluginResult = storagePlugin->setSecret(secret.identifier().collectionName(), hashedSecretName, encryptedName, encrypted, secret.filterData());
        }
    }
    return pluginResult;
}

SecretResult StoragePluginWrapper::getAndDecryptSecret(
        EncryptionPlugin *encryptionPlugin,
        StoragePlugin *storagePlugin,
        const Secret::Identifier &identifier,
        const QString &hashedSecretName,
        const QByteArray &encryptionKey)
{
    Secret secret;
    QByteArray encrypted, encryptedName;
    Secret::FilterData filterData;
    Result pluginResult = storagePlugin->getSecret(identifier.collectionName(), hashedSecretName, &encryptedName, &encrypted, &filterData);
    if (pluginResult.code() == Result::Succeeded) {
        QByteArray decrypted;
        pluginResult = encryptionPlugin->decryptSecret(encrypted, encryptionKey, &decrypted);
        secret.setData(decrypted);
        secret.setIdentifier(identifier);
        secret.setFilterData(filterData);
    }

    return SecretResult(pluginResult, secret);
}

IdentifiersResult
StoragePluginWrapper::findAndDecryptSecretNames(
        EncryptionPlugin *encryptionPlugin,
        StoragePlugin *storagePlugin,
        const QString &collectionName,
        std::pair<Sailfish::Secrets::Secret::FilterData,
                  Sailfish::Secrets::StoragePlugin::FilterOperator> filter,
        const QByteArray &encryptionKey)
{
    QVector<Secret::Identifier> identifiers;
    QVector<QByteArray> encryptedSecretNames;
    Result pluginResult = storagePlugin->findSecrets(collectionName, std::get<0>(filter), std::get<1>(filter), &encryptedSecretNames);
    if (pluginResult.code() == Result::Succeeded) {
        // decrypt each of the secret names.
        QVector<QString> decryptedSecretNames;
        bool decryptionSucceeded = true;
        for (const QByteArray &esn : encryptedSecretNames) {
            QByteArray decryptedName;
            pluginResult = encryptionPlugin->decryptSecret(esn, encryptionKey, &decryptedName);
            if (pluginResult.code() != Result::Succeeded) {
                decryptionSucceeded = false;
                break;
            }
            decryptedSecretNames.append(QString::fromUtf8(decryptedName));
        }
        if (decryptionSucceeded) {
            for (const QString &secretName : decryptedSecretNames) {
                identifiers.append(Secret::Identifier(secretName, collectionName));
            }
        }
    }

    return IdentifiersResult(pluginResult, identifiers);
}

bool EncryptedStoragePluginWrapper::isLocked(EncryptedStoragePlugin *plugin)
{
    return plugin->isLocked();
}

bool EncryptedStoragePluginWrapper::lock(EncryptedStoragePlugin *plugin)
{
    return plugin->lock();
}

bool EncryptedStoragePluginWrapper::unlock(
        EncryptedStoragePlugin *plugin,
        const QByteArray &lockCode)
{
    return plugin->unlock(lockCode);
}

bool EncryptedStoragePluginWrapper::setLockCode(
        EncryptedStoragePlugin *plugin,
        const QByteArray &oldLockCode,
        const QByteArray &newLockCode)
{
    return plugin->setLockCode(oldLockCode, newLockCode);
}

Result EncryptedStoragePluginWrapper::createCollection(
        EncryptedStoragePlugin *plugin,
        const QString &collectionName,
        const QByteArray &key)
{
    return plugin->createCollection(collectionName, key);
}

Result EncryptedStoragePluginWrapper::removeCollection(
        EncryptedStoragePlugin *plugin,
        const QString &collectionName)
{
    return plugin->removeCollection(collectionName);
}

EncryptedStoragePluginWrapper::LockedResult
EncryptedStoragePluginWrapper::isCollectionLocked(
        EncryptedStoragePlugin *plugin,
        const QString &collectionName)
{
    bool locked = false;
    Result result = plugin->isCollectionLocked(collectionName, &locked);
    return EncryptedStoragePluginWrapper::LockedResult(result, locked);
}

DerivedKeyResult
EncryptedStoragePluginWrapper::deriveKeyFromCode(
        EncryptedStoragePlugin *plugin,
        const QByteArray &authenticationCode,
        const QByteArray &salt)
{
    QByteArray key;
    Result result = plugin->deriveKeyFromCode(authenticationCode, salt, &key);
    return DerivedKeyResult(result, key);
}

Result EncryptedStoragePluginWrapper::setEncryptionKey(
        EncryptedStoragePlugin *plugin,
        const QString &collectionName,
        const QByteArray &key)
{
    return plugin->setEncryptionKey(collectionName, key);
}

Result EncryptedStoragePluginWrapper::reencrypt(
        EncryptedStoragePlugin *plugin,
        const QString &collectionName,
        const QByteArray &oldkey,
        const QByteArray &newkey)
{
    return plugin->reencrypt(collectionName,
                             oldkey,
                             newkey);
}

Result EncryptedStoragePluginWrapper::setSecret(
        EncryptedStoragePlugin *plugin,
        const QString &collectionName,
        const QString &hashedSecretName,
        const QString &secretName,
        const QByteArray &secret,
        const Secret::FilterData &filterData)
{
    return plugin->setSecret(collectionName,
                             hashedSecretName,
                             secretName,
                             secret,
                             filterData);
}

EncryptedStoragePluginWrapper::SecretDataResult
EncryptedStoragePluginWrapper::getSecret(
        EncryptedStoragePlugin *plugin,
        const QString &collectionName,
        const QString &hashedSecretName)
{
    QString secretName;
    QByteArray secret;
    Secret::FilterData filterData;
    Result result = plugin->getSecret(collectionName,
                                      hashedSecretName,
                                      &secretName,
                                      &secret,
                                      &filterData);
    return EncryptedStoragePluginWrapper::SecretDataResult(
                result, secretName, secret, filterData);
}

IdentifiersResult
EncryptedStoragePluginWrapper::findSecrets(
        EncryptedStoragePlugin *plugin,
        const QString &collectionName,
        const Secret::FilterData &filter,
        StoragePlugin::FilterOperator filterOperator)
{
    QVector<Secret::Identifier> identifiers;
    Result result = plugin->findSecrets(collectionName,
                                        filter,
                                        filterOperator,
                                        &identifiers);
    return IdentifiersResult(result, identifiers);
}

Result EncryptedStoragePluginWrapper::removeSecret(
        EncryptedStoragePlugin *plugin,
        const QString &collectionName,
        const QString &hashedSecretName)
{
    return plugin->removeSecret(collectionName,
                                hashedSecretName);
}

Result EncryptedStoragePluginWrapper::setSecret(
        EncryptedStoragePlugin *plugin,
        const QString &collectionName,
        const QString &hashedSecretName,
        const Secret &secret,
        const QByteArray &key)
{
    return plugin->setSecret(collectionName,
                             hashedSecretName,
                             secret.identifier().name(),
                             secret.data(),
                             secret.filterData(),
                             key);
}

EncryptedStoragePluginWrapper::SecretDataResult
EncryptedStoragePluginWrapper::accessSecret(
        EncryptedStoragePlugin *plugin,
        const QString &collectionName,
        const QString &hashedSecretName,
        const QByteArray &key)
{
    QString secretName;
    QByteArray secret;
    Secret::FilterData filterData;
    Result result = plugin->accessSecret(collectionName,
                                         hashedSecretName,
                                         key,
                                         &secretName,
                                         &secret,
                                         &filterData);
    return EncryptedStoragePluginWrapper::SecretDataResult(
                result, secretName, secret, filterData);
}


Result EncryptedStoragePluginWrapper::unlockCollectionAndStoreSecret(
        EncryptedStoragePlugin *plugin,
        const Secret &secret,
        const QString &hashedSecretName,
        const QByteArray &encryptionKey)
{
    bool locked = false;
    Result pluginResult = plugin->isCollectionLocked(secret.identifier().collectionName(), &locked);
    if (pluginResult.code() == Result::Succeeded) {
        if (locked) {
            pluginResult = plugin->setEncryptionKey(secret.identifier().collectionName(), encryptionKey);
            if (pluginResult.code() != Result::Succeeded) {
                // unable to apply the new encryptionKey.
                plugin->setEncryptionKey(secret.identifier().collectionName(), QByteArray());
                return Result(Result::SecretsPluginDecryptionError,
                              QString::fromLatin1("Unable to decrypt collection %1 with the entered authentication key").arg(secret.identifier().collectionName()));

            }
            pluginResult = plugin->isCollectionLocked(secret.identifier().collectionName(), &locked);
            if (pluginResult.code() != Result::Succeeded) {
                plugin->setEncryptionKey(secret.identifier().collectionName(), QByteArray());
                return Result(Result::SecretsPluginDecryptionError,
                              QString::fromLatin1("Unable to check lock state of collection %1 after setting the entered authentication key").arg(secret.identifier().collectionName()));

            }
        }
        if (locked) {
            // still locked, even after applying the new encryptionKey?  The authenticationCode was wrong.
            plugin->setEncryptionKey(secret.identifier().collectionName(), QByteArray());
            return Result(Result::IncorrectAuthenticationCodeError,
                          QString::fromLatin1("The authentication code entered for collection %1 was incorrect").arg(secret.identifier().collectionName()));
        } else {
            // successfully unlocked the encrypted storage collection.  write the secret.
            pluginResult = plugin->setSecret(secret.identifier().collectionName(), hashedSecretName, secret.identifier().name(), secret.data(), secret.filterData());
        }
    }
    return pluginResult;
}

SecretResult EncryptedStoragePluginWrapper::unlockCollectionAndReadSecret(
        EncryptedStoragePlugin *plugin,
        const Secret::Identifier &identifier,
        const QString &hashedSecretName,
        const QByteArray &encryptionKey)
{
    Secret secret;
    bool locked = false;
    Result pluginResult = plugin->isCollectionLocked(identifier.collectionName(), &locked);
    if (pluginResult.code() != Result::Succeeded) {
        return SecretResult(pluginResult, secret);
    }

    // if it's locked, attempt to unlock it
    if (locked) {
        pluginResult = plugin->setEncryptionKey(identifier.collectionName(), encryptionKey);
        if (pluginResult.code() != Result::Succeeded) {
            // unable to apply the new encryptionKey.
            plugin->setEncryptionKey(identifier.collectionName(), QByteArray());
            return SecretResult(Result(Result::SecretsPluginDecryptionError,
                                       QString::fromLatin1("Unable to decrypt collection %1 with the entered authentication key")
                                       .arg(identifier.collectionName())),
                                secret);

        }
        pluginResult = plugin->isCollectionLocked(identifier.collectionName(), &locked);
        if (pluginResult.code() != Result::Succeeded) {
            plugin->setEncryptionKey(identifier.collectionName(), QByteArray());
            return SecretResult(Result(Result::SecretsPluginDecryptionError,
                                       QString::fromLatin1("Unable to check lock state of collection %1 after setting the entered authentication key")
                                       .arg(identifier.collectionName())),
                                secret);

        }
    }

    if (locked) {
        // still locked, even after applying the new encryptionKey?  The authenticationCode was wrong.
        plugin->setEncryptionKey(identifier.collectionName(), QByteArray());
        return SecretResult(Result(Result::IncorrectAuthenticationCodeError,
                                   QString::fromLatin1("The authentication code entered for collection %1 was incorrect")
                                   .arg(identifier.collectionName())),
                            secret);
    }

    // successfully unlocked the encrypted storage collection.  read the secret.
    QString secretName;
    QByteArray secretData;
    Secret::FilterData secretFilterdata;
    pluginResult = plugin->getSecret(identifier.collectionName(), hashedSecretName, &secretName, &secretData, &secretFilterdata);
    secret.setData(secretData);
    secret.setFilterData(secretFilterdata);
    secret.setIdentifier(identifier);
    return SecretResult(pluginResult, secret);
}

Result EncryptedStoragePluginWrapper::unlockCollectionAndRemoveSecret(
        EncryptedStoragePlugin *plugin,
        const Secret::Identifier &identifier,
        const QString &hashedSecretName,
        const QByteArray &encryptionKey)
{
    bool locked = false;
    Result pluginResult = plugin->isCollectionLocked(identifier.collectionName(), &locked);
    if (pluginResult.code() != Result::Succeeded) {
        return pluginResult;
    }

    // if it's locked, attempt to unlock it
    if (locked) {
        pluginResult = plugin->setEncryptionKey(identifier.collectionName(), encryptionKey);
        if (pluginResult.code() != Result::Succeeded) {
            // unable to apply the new encryptionKey.
            plugin->setEncryptionKey(identifier.collectionName(), QByteArray());
            return Result(Result::SecretsPluginDecryptionError,
                          QString::fromLatin1("Unable to decrypt collection %1 with the entered authentication key").arg(identifier.collectionName()));

        }
        pluginResult = plugin->isCollectionLocked(identifier.collectionName(), &locked);
        if (pluginResult.code() != Result::Succeeded) {
            plugin->setEncryptionKey(identifier.collectionName(), QByteArray());
            return Result(Result::SecretsPluginDecryptionError,
                          QString::fromLatin1("Unable to check lock state of collection %1 after setting the entered authentication key").arg(identifier.collectionName()));

        }
    }
    if (locked) {
        // still locked, even after applying the new encryptionKey?  The authenticationCode was wrong.
        plugin->setEncryptionKey(identifier.collectionName(), QByteArray());
        return Result(Result::IncorrectAuthenticationCodeError,
                      QString::fromLatin1("The authentication code entered for collection %1 was incorrect").arg(identifier.collectionName()));
    }

    // successfully unlocked the encrypted storage collection.  remove the secret.
    pluginResult = plugin->removeSecret(identifier.collectionName(), hashedSecretName);
    return pluginResult;
}

IdentifiersResult
EncryptedStoragePluginWrapper::unlockAndFindSecrets(
        EncryptedStoragePlugin *plugin,
        const QString &collectionName,
        const Secret::FilterData &filter,
        StoragePlugin::FilterOperator filterOperator,
        const QByteArray &encryptionKey)
{
    QVector<Secret::Identifier> identifiers;
    bool locked = false;
    Result pluginResult = plugin->isCollectionLocked(collectionName, &locked);
    if (pluginResult.code() != Result::Succeeded) {
        return IdentifiersResult(pluginResult, identifiers);
    }

    // if it's locked, attempt to unlock it
    if (locked) {
        pluginResult = plugin->setEncryptionKey(collectionName, encryptionKey);
        if (pluginResult.code() != Result::Succeeded) {
            // unable to apply the new encryptionKey.
            plugin->setEncryptionKey(collectionName, QByteArray());
            return IdentifiersResult(Result(Result::SecretsPluginDecryptionError,
                                            QString::fromLatin1("Unable to decrypt collection %1 with the entered authentication key")
                                            .arg(collectionName)),
                                     identifiers);

        }
        pluginResult = plugin->isCollectionLocked(collectionName, &locked);
        if (pluginResult.code() != Result::Succeeded) {
            plugin->setEncryptionKey(collectionName, QByteArray());
            return IdentifiersResult(Result(Result::SecretsPluginDecryptionError,
                                            QString::fromLatin1("Unable to check lock state of collection %1 after setting the entered authentication key")
                                            .arg(collectionName)),
                                     identifiers);

        }
    }

    if (locked) {
        // still locked, even after applying the new encryptionKey?  The authenticationCode was wrong.
        plugin->setEncryptionKey(collectionName, QByteArray());
        return IdentifiersResult(Result(Result::IncorrectAuthenticationCodeError,
                                        QString::fromLatin1("The authentication code entered for collection %1 was incorrect")
                                        .arg(collectionName)),
                                 identifiers);
    }

    // successfully unlocked the encrypted storage collection.  perform the filtering operation.
    pluginResult = plugin->findSecrets(collectionName, filter, static_cast<StoragePlugin::FilterOperator>(filterOperator), &identifiers);
    return IdentifiersResult(pluginResult, identifiers);
}

Result EncryptedStoragePluginWrapper::unlockAndRemoveSecret(
        EncryptedStoragePlugin *plugin,
        const QString &collectionName,
        const QString &hashedSecretName,
        bool secretUsesDeviceLockKey,
        const QByteArray &deviceLockKey)
{
    bool locked = false;
    Result pluginResult = plugin->isCollectionLocked(collectionName, &locked);
    if (pluginResult.code() == Result::Failed) {
        return pluginResult;
    }
    if (locked && secretUsesDeviceLockKey) {
        pluginResult = plugin->setEncryptionKey(collectionName, deviceLockKey);
        if (pluginResult.code() == Result::Failed) {
            return pluginResult;
        }
    }
    pluginResult = plugin->removeSecret(collectionName, hashedSecretName);
    if (locked) {
        // relock after delete-access.
        plugin->setEncryptionKey(collectionName, QByteArray());
    }

    return pluginResult;
}

Result EncryptedStoragePluginWrapper::unlockCollectionAndReencrypt(
        EncryptedStoragePlugin *plugin,
        const QString &collectionName,
        const QByteArray &oldEncryptionKey,
        const QByteArray &newEncryptionKey,
        bool isDeviceLocked)
{
    bool collectionLocked = true;
    plugin->isCollectionLocked(collectionName, &collectionLocked);
    if (collectionLocked) {
        Result collectionUnlockResult = plugin->setEncryptionKey(collectionName, oldEncryptionKey);
        if (collectionUnlockResult.code() != Result::Succeeded) {
            qCWarning(lcSailfishSecretsDaemon) << "Error unlocking"
                                               << (isDeviceLocked ? "device-locked" : "custom-locked")
                                               << "collection:" << collectionName
                                               << collectionUnlockResult.errorMessage();
        }
        plugin->isCollectionLocked(collectionName, &collectionLocked);
        if (collectionLocked) {
            qCWarning(lcSailfishSecretsDaemon) << "Failed to unlock"
                                               << (isDeviceLocked ? "device-locked" : "custom-locked")
                                               << "collection:" << collectionName;
        }
    }
    Result collectionReencryptResult = plugin->reencrypt(
                collectionName, oldEncryptionKey, newEncryptionKey);
    if (collectionReencryptResult.code() != Result::Succeeded) {
        qCWarning(lcSailfishSecretsDaemon) << "Failed to re-encrypt encrypted storage"
                                           << (isDeviceLocked ? "device-locked" : "custom-locked")
                                           << "collection:" << collectionName
                                           << collectionReencryptResult.code()
                                           << collectionReencryptResult.errorMessage();
    }
    return collectionReencryptResult;
}