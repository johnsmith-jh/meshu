/**
 * Minimal Web Bluetooth ambient types (Android Chrome subset used by meshu).
 * The full @types/web-bluetooth package is larger than we need; these cover
 * requestDevice + NUS GATT access. @ts-nocheck'd call sites stay typed loosely
 * on purpose — the browser is the only executor of this file.
 */

interface BluetoothRemoteGATTCharacteristic extends EventTarget {
  readonly value: DataView | null;
  writeValueWithResponse(value: BufferSource): Promise<void>;
  startNotifications(): Promise<BluetoothRemoteGATTCharacteristic>;
}

interface BluetoothRemoteGATTService {
  getCharacteristic(characteristic: string): Promise<BluetoothRemoteGATTCharacteristic>;
}

interface BluetoothRemoteGATTServer {
  connected: boolean;
  connect(): Promise<BluetoothRemoteGATTServer>;
  disconnect(): void;
  getPrimaryService(service: string): Promise<BluetoothRemoteGATTService>;
}

interface BluetoothDevice extends EventTarget {
  readonly name?: string;
  readonly gatt?: BluetoothRemoteGATTServer;
}

interface Bluetooth {
  requestDevice(options: {
    filters: Array<{ services: Array<string> }>;
  }): Promise<BluetoothDevice>;
}

interface Navigator {
  readonly bluetooth?: Bluetooth;
}
