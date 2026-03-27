import { Log } from "../../types/log";
import { IngestionResult } from "./types";

export interface IIngestionCoordinator {
    handle(raw: Partial<Log>): Promise<IngestionResult>;
}

export interface ILogNormalizer {
    normalize(raw: Partial<Log>): Log;
}
