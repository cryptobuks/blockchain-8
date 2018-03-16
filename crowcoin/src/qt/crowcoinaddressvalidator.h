// Copyright (c) 2011-2014 The Crowcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef CROWCOIN_QT_CROWCOINADDRESSVALIDATOR_H
#define CROWCOIN_QT_CROWCOINADDRESSVALIDATOR_H

#include <QValidator>

/** Base58 entry widget validator, checks for valid characters and
 * removes some whitespace.
 */
class CrowcoinAddressEntryValidator : public QValidator
{
    Q_OBJECT

public:
    explicit CrowcoinAddressEntryValidator(QObject *parent);

    State validate(QString &input, int &pos) const;
};

/** Crowcoin address widget validator, checks for a valid crowcoin address.
 */
class CrowcoinAddressCheckValidator : public QValidator
{
    Q_OBJECT

public:
    explicit CrowcoinAddressCheckValidator(QObject *parent);

    State validate(QString &input, int &pos) const;
};

#endif // CROWCOIN_QT_CROWCOINADDRESSVALIDATOR_H
