// The Wallet route: the shared wallet, with the two things only this site has
// above it — the account-health panel and, for the operator npub alone, the
// operator's dependencies.

import { Wallet } from "@tollbooth-dpyc/web/react";
import { PatronFundingStatus, OperatorFundingStatus } from "./FundingStatusPanels";

export default function WalletPage() {
  return (
    <div className="max-w-3xl mx-auto px-4 py-6 space-y-5">
      <PatronFundingStatus />
      <OperatorFundingStatus />
      <Wallet />
    </div>
  );
}
