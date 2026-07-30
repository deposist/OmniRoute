export type ProviderCredentials = Record<string, unknown>;
export type ExecuteInput = Record<string, unknown>;

export class BaseExecutor {
  constructor(
    public provider: string,
    public config: Record<string, unknown>
  ) {}
}
