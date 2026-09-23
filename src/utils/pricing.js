export const formatPkr = (value) =>
  new Intl.NumberFormat("en-PK", {
    style: "currency",
    currency: "PKR",
    maximumFractionDigits: 0,
  }).format(Number(value) || 0);

export const calculatePricingEstimate = (catalog, selection) => {
  if (!catalog) return null;

  const endpoints = Math.min(
    Number(catalog.maximum_endpoints) || 50,
    Math.max(Number(catalog.minimum_endpoints) || 10, Number(selection.endpoints) || 10),
  );
  const endpointMonthly = endpoints * Number(catalog.endpoint_monthly_price || 0);
  const packPrices = catalog.compliance_pack_monthly_prices || {};
  const complianceMonthly =
    (selection.addons?.fbr ? Number(packPrices.fbr_pos || 0) : 0) +
    (selection.addons?.peca ? Number(packPrices.peca_forensic || 0) : 0);
  const monthlyRecurring = endpointMonthly + complianceMonthly;
  const periodMonths = selection.cycle === "yearly" ? Number(catalog.annual_months || 12) : 1;
  const recurringTotal = monthlyRecurring * periodMonths;
  const setupFee = Number(catalog.one_time_setup_fee || 0);

  return {
    endpoints,
    endpointMonthly,
    complianceMonthly,
    monthlyRecurring,
    periodMonths,
    recurringTotal,
    setupFee,
    firstInvoice: recurringTotal + setupFee,
  };
};
