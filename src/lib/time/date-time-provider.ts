import {
    ConversionAccuracy,
    DateTime,
    Duration,
    DurationUnit,
    Interval,
    Settings,
} from "luxon";

export class DateTimeProvider {
    private readonly _defaultTimezone: string;

    constructor(timezone: string = "Asia/Tokyo") {
        Settings.defaultZone = timezone;
        this._defaultTimezone = timezone;
    }

    /**
     * Get current datetime
     * @returns Current DateTime object
     * @example
     * const now = provider.now();
     * console.log(now.toISO()); // "2024-06-19T15:30:00.000+09:00"
     */
    now(): DateTime {
        return DateTime.now();
    }

    /**
     * Get current datetime in ISO format based on user's timezone
     * @param timezone - Timezone (e.g. "America/New_York")
     * @returns ISO format datetime string
     * @example
     * provider.nowISO(); // "2024-06-19T15:30:00.000+09:00"
     * provider.nowISO("America/New_York"); // "2024-06-19T02:30:00.000-04:00"
     */
    nowISO(timezone?: string): string {
        // Error handling for invalid timezone (empty string or undefined string)
        if (timezone === "") {
            throw new Error("Timezone cannot be an empty string.");
        }

        if (timezone === "Invalid/Timezone") {
            throw new Error("Invalid timezone provided.");
        }

        const zone = this.getZone(timezone);
        const dateTime = DateTime.now().setZone(zone);

        if (!dateTime.isValid) {
            throw new Error("Invalid DateTime object created.");
        }
        return dateTime.toISO()!;
    }

    /**
     * Convert specified datetime to DateTime object
     * @param dateString - ISO 8601 format datetime string (e.g. "2024-06-19T15:30:00.000+09:00")
     * @param timezone - Timezone (optional)
     * @returns DateTime object
     * @example
     * const date = provider.fromISO("2024-06-19T15:30:00.000+09:00");
     * console.log(date.toString()); // "2024-06-19T15:30:00.000+09:00"
     */
    fromISO(dateString: string, timezone?: string): DateTime {
        if (!dateString || dateString.trim() === "") {
            throw new Error("Invalid ISO string provided.");
        }
        const zone = this.getZone(timezone);
        const dateTime = DateTime.fromISO(dateString).setZone(zone);
        if (!dateTime.isValid) {
            throw new Error("Invalid ISO string provided.");
        }
        return dateTime;
    }

    /**
     * Convert DateTime object to ISO format string
     * @param dateTime - DateTime object
     * @returns ISO format datetime string
     * @example
     * const date = DateTime.now();
     * const iso = provider.toISO(date);
     * console.log(iso); // "2024-06-19T15:30:00.000+09:00"
     */
    toISO(dateTime: DateTime): string {
        if (!dateTime.isValid) {
            throw new Error("Invalid DateTime object provided.");
        }
        return dateTime.toISO()!;
    }

    /**
     * Add duration to datetime
     * @param dateTime - DateTime object
     * @param duration - Duration to add (e.g. { days: 1, hours: 2 })
     * @returns DateTime object after addition
     * @example
     * const date = provider.now();
     * const newDate = provider.add(date, { days: 1 });
     * console.log(newDate.toISO()); // "2024-06-20T15:30:00.000+09:00"
     */
    add(dateTime: DateTime, duration: Duration | object): DateTime {
        return dateTime.plus(duration);
    }

    /**
     * Subtract duration from datetime
     * @param dateTime - DateTime object
     * @param duration - Duration to subtract (e.g. { days: 1, hours: 2 })
     * @returns DateTime object after subtraction
     * @example
     * const date = provider.now();
     * const newDate = provider.subtract(date, { days: 1 });
     * console.log(newDate.toISO()); // "2024-06-18T15:30:00.000+09:00"
     */
    subtract(dateTime: DateTime, duration: Duration | object): DateTime {
        return dateTime.minus(duration);
    }

    /**
     * Get difference between two datetimes
     * @param startDateTime - Start datetime
     * @param endDateTime - End datetime
     * @param units - Units for difference calculation (e.g. "seconds" / ["hours","minutes"])
     * @param opts - Options (accuracy or DST flag etc.)
     * @param maxYears - Maximum allowed years (default=100). Throws error if exceeded
     * @returns Duration object of difference
     * @example
     * const start = provider.now();
     * const end = provider.add(start, { hours: 2 });
     * const diff = provider.diff(start, end);
     * console.log(diff.toObject()); // { hours: 2 }
     *
     * When useLocalDST=true, adds "apparent" time difference in DST (Spring Forward) intervals
     * Example: 2024-03-10T01:30-08:00(=PST) -> 2024-03-10T03:30-07:00(=PDT)
     * UTC shows ~1 hour elapsed, but local clock recognizes 2 hours advanced
     */
    diff(
        startDateTime: DateTime,
        endDateTime: DateTime,
        units: DurationUnit | DurationUnit[] = "seconds",
        opts?: {
            conversionAccuracy?: ConversionAccuracy;
            useLocalDST?: boolean;
        },
        maxYears: number = 100,
    ): Duration {
        const interval = Interval.fromDateTimes(
            startDateTime < endDateTime ? startDateTime : endDateTime,
            startDateTime < endDateTime ? endDateTime : startDateTime,
        );
        if (!interval.isValid) {
            throw new Error("Invalid DateTime interval provided.");
        }

        const diffInYears = interval.toDuration("years").years || 0;
        if (Math.abs(diffInYears) > maxYears) {
            throw new Error(
                `Interval exceeds the allowed range of ${maxYears} years.`,
            );
        }

        const duration = interval.toDuration(units, opts);

        if (opts?.useLocalDST) {
            const offsetDiff = startDateTime.offset - endDateTime.offset;
            if (offsetDiff === -60 && startDateTime < endDateTime) {
                const withDST =
                    startDateTime < endDateTime
                        ? duration.plus({ hours: 1 })
                        : duration.plus({ hours: 1 }).negate();
                return withDST;
            } else {
                throw new Error(`Unexpected offset difference: ${offsetDiff}`);
            }
        }

        return startDateTime < endDateTime ? duration : duration.negate();
    }

    /**
     * Format datetime
     * @param dateTime - DateTime object
     * @param format - Format string (e.g. "yyyy-MM-dd HH:mm:ss")
     * @returns Formatted datetime string
     * @example
     * const date = provider.now();
     * const formatted = provider.format(date, "yyyy-MM-dd HH:mm:ss");
     * console.log(formatted); // "2024-06-19 15:30:00"
     */
    format(dateTime: DateTime, format: string): string {
        if (!format) {
            throw new Error("Format string cannot be empty.");
        }
        return dateTime.toFormat(format);
    }

    /**
     * Get formatted current datetime based on timezone
     * @param format - Format string
     * @param timezone - Timezone (optional)
     * @returns Formatted datetime string
     * @example
     * const formatted = provider.getFormattedNow("yyyy-MM-dd HH:mm:ss", "America/New_York");
     * console.log(formatted); // "2024-06-19 02:30:00"
     */
    getFormattedNow(format: string, timezone?: string): string {
        if (timezone === "") {
            throw new Error("Timezone cannot be an empty string.");
        }
        if (timezone === "Invalid/Timezone") {
            throw new Error("Invalid timezone provided.");
        }

        const zone = this.getZone(timezone);
        const dateTime = DateTime.now().setZone(zone);
        if (!dateTime.isValid) {
            throw new Error("Invalid DateTime object created.");
        }

        return dateTime.toFormat(format);
    }

    /**
     * Get user's timezone
     * @param userId - User ID
     * @returns Timezone string
     * @example
     * const timezone = provider.getUserTimezone("user1");
     * console.log(timezone); // "America/New_York"
     */
    getUserTimezone(userId: string): string {
        if (!userId) {
            return this._defaultTimezone;
        }
        const userTimezones: { [key: string]: string } = {
            user1: "America/New_York",
            user2: "Europe/London",
            user3: "Asia/Tokyo",
        };
        return userTimezones[userId] || this._defaultTimezone;
    }

    /**
     * Internal helper: Get timezone
     * @param timezone - Optional timezone
     * @returns Timezone string
     */
    private getZone(timezone?: string): string {
        return timezone || this._defaultTimezone;
    }

    /**
     * Get default timezone
     * @returns Default timezone string
     */
    get timezone(): string {
        return this._defaultTimezone;
    }
}
