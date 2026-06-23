// =============================================================================
// Local type shim for `ioredis-mock`.
//
// `ioredis-mock` does not ship its own .d.ts and `@types/ioredis-mock` is
// not a dependency of this SDK. The package's runtime surface is a
// superset of the ioredis methods we actually call (get, set, del,
// scan), so a minimal structural declaration is enough to satisfy
// `strict: true` under ts-jest.
//
// If the SDK ever adopts `ioredis-mock` as a real test dependency,
// delete this file and add `@types/ioredis-mock` to devDependencies.
// =============================================================================

declare module 'ioredis-mock' {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  class RedisMock extends Map<string, any> implements any {}

  namespace RedisMock {}

  // eslint-disable-next-line import/no-default-export
  export default RedisMock;
}