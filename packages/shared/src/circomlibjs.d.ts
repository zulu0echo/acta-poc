declare module 'circomlibjs' {
  // Minimal typing shim for dynamic import.
  // We intentionally keep this loose because circomlibjs is an optional
  // production dependency in this repository.
  export function buildPoseidon(...args: unknown[]): Promise<any>
}

