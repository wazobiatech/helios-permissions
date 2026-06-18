// =============================================================================
// NestJS module — forRoot() factory + PERMISSION_CLIENT injection token.
//
// Usage:
//   @Module({
//     imports: [
//       PermissionsModule.forRoot({
//         heliosBaseUrl: process.env.HELIOS_BASE_URL!,
//         heliosHmacSecret: process.env.HELIOS_HMAC_SECRET!,
//         heliosProjectToken: process.env.HELIOS_PROJECT_TOKEN!,
//         redisUrl: process.env.PERMISSION_REDIS_URL!,
//       }),
//     ],
//   })
//   export class AppModule {}
//
//   constructor(@Inject(PERMISSION_CLIENT) private readonly perms: PermissionClient) {}
//
// forRootAsync is also exported for config-driven bootstrapping.
// =============================================================================

import {
  type DynamicModule,
  Global,
  Inject,
  type InjectionToken,
  Module,
  type Provider,
} from '@nestjs/common';

import { PermissionClient } from '../permission-client';
import {
  createPermissionClient,
  type CreatePermissionClientOptions,
  type CreatePermissionClientResult,
} from '../factory';

/** Injection token for PermissionClient. Use @Inject(PERMISSION_CLIENT). */
export const PERMISSION_CLIENT = Symbol('PERMISSION_CLIENT');

/** Injection token for the factory result's `close` function (Redis cleanup). */
export const PERMISSION_CLIENT_CLEANUP = Symbol('PERMISSION_CLIENT_CLEANUP');

@Global()
@Module({})
export class PermissionsModule {
  static forRoot(opts: CreatePermissionClientOptions): DynamicModule {
    const clientProvider: Provider = {
      provide: PERMISSION_CLIENT,
      useFactory: (): PermissionClient => createPermissionClient(opts).client,
    };

    return {
      module: PermissionsModule,
      providers: [clientProvider],
      exports: [clientProvider],
    };
  }

  static forRootAsync(opts: {
    imports?: DynamicModule['imports'];
    useFactory: (...args: unknown[]) => Promise<CreatePermissionClientOptions> | CreatePermissionClientOptions;
    inject?: InjectionToken[];
  }): DynamicModule {
    const optionsProvider: Provider = {
      provide: 'PERMISSION_CLIENT_OPTIONS',
      useFactory: opts.useFactory,
      inject: opts.inject ?? [],
    };

    const resultProvider: Provider = {
      provide: 'PERMISSION_CLIENT_RESULT',
      useFactory: (clientOpts: CreatePermissionClientOptions): CreatePermissionClientResult =>
        createPermissionClient(clientOpts),
      inject: ['PERMISSION_CLIENT_OPTIONS'],
    };

    const clientProvider: Provider = {
      provide: PERMISSION_CLIENT,
      useFactory: (result: CreatePermissionClientResult): PermissionClient => result.client,
      inject: ['PERMISSION_CLIENT_RESULT'],
    };

    const cleanupProvider: Provider = {
      provide: PERMISSION_CLIENT_CLEANUP,
      useFactory: async (result: CreatePermissionClientResult): Promise<() => Promise<void>> => {
        // Capture the close fn and ensure it's called on module destroy.
        return async () => {
          await result.close();
        };
      },
      inject: ['PERMISSION_CLIENT_RESULT'],
    };

    return {
      module: PermissionsModule,
      imports: opts.imports ?? [],
      providers: [optionsProvider, resultProvider, clientProvider, cleanupProvider],
      exports: [clientProvider],
    };
  }
}

/** Convenience: inject PERMISSION_CLIENT with proper type. */
export const InjectPermissionClient = (): ParameterDecorator => Inject(PERMISSION_CLIENT);
