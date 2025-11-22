const UNIT_IN_SECONDS: Record<string, number> = {
  s: 1,
  m: 60,
  h: 60 * 60,
  d: 24 * 60 * 60,
};

/**
 * Parse duration strings like "10m", "2h 30m", "7d", or plain seconds ("600")
 * into total seconds.
 */
export const parseDurationToSeconds = (value: string | number): number => {
  if (typeof value === 'number') {
    if (!Number.isFinite(value) || value <= 0) {
      throw new Error('Duration must be a positive number');
    }
    return Math.floor(value);
  }

  const trimmed = value.trim();
  if (!trimmed) {
    throw new Error('Duration string cannot be empty');
  }

  const numeric = Number(trimmed);
  if (!Number.isNaN(numeric)) {
    if (numeric <= 0) {
      throw new Error('Duration must be positive');
    }
    return Math.floor(numeric);
  }

  const regex = /(\d+(?:\.\d+)?)\s*([smhd])/gi;
  let totalSeconds = 0;
  let matched = false;
  let lastIndex = 0;

  let match: RegExpExecArray | null;
  while ((match = regex.exec(trimmed)) !== null) {
    if (match.index > lastIndex) {
      const gap = trimmed.slice(lastIndex, match.index).trim();
      if (gap) {
        throw new Error(`Invalid duration format: "${value}"`);
      }
    }

    matched = true;
    const amount = Number(match[1]);
    const unit = match[2].toLowerCase();
    const seconds = UNIT_IN_SECONDS[unit];
    if (!seconds || amount <= 0) {
      throw new Error(`Invalid duration segment: "${match[0]}"`);
    }
    totalSeconds += amount * seconds;
    lastIndex = regex.lastIndex;
  }

  if (!matched || trimmed.slice(lastIndex).trim().length > 0) {
    throw new Error(`Invalid duration format: "${value}"`);
  }

  return Math.floor(totalSeconds);
};

export const formatSecondsToHuman = (seconds: number): string => {
  if (!Number.isFinite(seconds) || seconds < 0) {
    throw new Error('Seconds must be a non-negative number');
  }

  const parts: string[] = [];
  let remaining = Math.floor(seconds);

  const pushPart = (value: number, label: string) => {
    if (value > 0) {
      parts.push(`${value}${label}`);
    }
  };

  const days = Math.floor(remaining / UNIT_IN_SECONDS.d);
  remaining -= days * UNIT_IN_SECONDS.d;
  const hours = Math.floor(remaining / UNIT_IN_SECONDS.h);
  remaining -= hours * UNIT_IN_SECONDS.h;
  const minutes = Math.floor(remaining / UNIT_IN_SECONDS.m);
  remaining -= minutes * UNIT_IN_SECONDS.m;

  pushPart(days, 'd');
  pushPart(hours, 'h');
  pushPart(minutes, 'm');
  pushPart(remaining, 's');

  return parts.length > 0 ? parts.join(' ') : '0s';
};
