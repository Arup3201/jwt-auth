var accessToken: string | null = null;

const tokenStore = {
  get: () => accessToken,
  set: (tkn: string) => (accessToken = tkn),
  clear: () => (accessToken = null),
};

export { tokenStore };
