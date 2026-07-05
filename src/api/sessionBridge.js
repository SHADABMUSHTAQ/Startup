let readCsrfToken = () => null;
let clearSession = () => {};

export const configureSessionBridge = ({
  getCsrfToken,
  onUnauthorized,
}) => {
  readCsrfToken =
    typeof getCsrfToken === "function" ? getCsrfToken : () => null;
  clearSession =
    typeof onUnauthorized === "function" ? onUnauthorized : () => {};
};

export const getSessionCsrfToken = () => readCsrfToken();

export const clearUnauthorizedSession = () => {
  clearSession();
};
