// ===============================
// Influx Measurements DTO
// ===============================

export interface NodeStatusDto {
  nodeId: string;
  collectAgentId: string;
  collectAgentVersion: string;

  collectionWindowSeconds: number;
  receivedTimestamp: number;

  cpuUsagePercent: number;
  memoryUsagePercent: number;
  memoryUsedBytes: number;
  memoryTotalBytes: number;

  timestamp: number; // epoch (ns or ms)
}

export interface GpuStatusDto {
  nodeId: string;
  gpuIndex: number;
  gpuName: string;

  utilizationPercent: number;
  temperatureCelsius: number;
  powerWatts: number;
  powerLimitWatts: number;
  memoryUsedMiB: number;
  memoryTotalMiB: number;

  timestamp: number;
}

export interface ProcessStatusDto {
  nodeId: string;
  comm: string;
  pid: number;
  processName: string;
  uid: number;

  cpuOntimeNs: number;
  readBytes: number;
  writeBytes: number;
  netRxBytes: number;
  netTxBytes: number;
  gpuUsedMemoryMiB: number;

  timestamp: number;
}

// ===============================
// Context
// ===============================

export interface JobContextDto {
  jobId: string;
  userAccount: string;
  startTime: Date;
  endTime: Date | null;
  allocatedNodes: string[];
}

// ===============================
// Timescale Aggregated Tables
// ===============================

export interface NodeStatusHourlyDto {
  bucketTime: Date;
  nodeId: string;

  avgCpuUsagePercent: number;
  maxCpuUsagePercent: number;

  avgMemUsagePercent: number;
  maxMemUsedBytes: number;

  avgGpuUtilization: number;
  maxGpuTemperature: number;
  totalGpuPowerWatts: number;

  totalDiskReadBytes: number;
  totalDiskWriteBytes: number;

  totalNetRxBytes: number;
  totalNetTxBytes: number;

  isActive: boolean;
}

export interface UserAppHourlyDto {
  bucketTime: Date;
  nodeId: string;
  uid: number;
  comm: string;

  totalCpuTimeSeconds: number;
  avgRssMemoryBytes: number;
  maxRssMemoryBytes: number;
  maxGpuMemoryMiB: number;

  totalReadBytes: number;
  totalWriteBytes: number;
  totalNetRxBytes: number;
  totalNetTxBytes: number;

  processCount: number;
}