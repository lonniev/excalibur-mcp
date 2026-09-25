// The Wallet route: the package's WalletPage (balance, Lightning top-up,
// tranches, statement) in eXcalibur's look, with the two things only this
// site has above the balance — the account-health panel and, for the
// operator npub alone, the operator's dependencies — and every date in the
// patron's chosen display zone. Coupons live on Profile, as they always have.

import { formatDate, formatDateTime } from "@tollbooth-dpyc/web";
import { WalletPage as SharedWalletPage, useTimezone } from "@tollbooth-dpyc/web/react";
import { walletStyles } from "../lib/packageStyles";
import { PatronFundingStatus, OperatorFundingStatus } from "./FundingStatusPanels";

export default function WalletPage() {
  const [, timeZone] = useTimezone();
  return (
    <SharedWalletPage
      classNames={walletStyles}
      coupons={false}
      formatDate={(iso) => formatDate(iso, timeZone)}
      formatDateTime={(iso) => formatDateTime(iso, timeZone)}
      before={
        <>
          <PatronFundingStatus />
          <OperatorFundingStatus />
        </>
      }
    />
  );
}
