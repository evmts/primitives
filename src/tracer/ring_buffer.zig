const std = @import("std");

/// Fixed-size ring buffer for tracking recent opcodes
/// Always active when tracer is enabled
pub const RingBuffer = struct {
    const CAPACITY = 10; // Last 10 opcodes

    pub const Entry = struct {
        step_number: u64,
        opcode: u16,
        opcode_name: []const u8,
        gas_before: i64,
        gas_after: i64,
        stack_size: u32,
        memory_size: u32,
        schedule_index: u32,
        is_synthetic: bool,
    };

    buffer: [CAPACITY]Entry = undefined,
    head: usize = 0,
    count: usize = 0,

    pub fn init() RingBuffer {
        return .{
            .buffer = undefined,
            .head = 0,
            .count = 0,
        };
    }

    pub fn write(self: *RingBuffer, entry: Entry) void {
        self.buffer[self.head] = entry;
        self.head = (self.head + 1) % CAPACITY;
        if (self.count < CAPACITY) self.count += 1;
    }

    pub fn read(self: *const RingBuffer) []const Entry {
        if (self.count == 0) return &[_]Entry{};
        if (self.count < CAPACITY) return self.buffer[0..self.count];
        return &self.buffer;
    }

    pub fn getOrdered(self: *const RingBuffer, out: *[CAPACITY]Entry) []Entry {
        if (self.count == 0) return out[0..0];
        if (self.count < CAPACITY) {
            @memcpy(out[0..self.count], self.buffer[0..self.count]);
            return out[0..self.count];
        }

        const oldest_idx = self.head;
        const newer_count = CAPACITY - oldest_idx;

        @memcpy(out[0..newer_count], self.buffer[oldest_idx..CAPACITY]);
        if (oldest_idx > 0) @memcpy(out[newer_count..CAPACITY], self.buffer[0..oldest_idx]);

        return out[0..CAPACITY];
    }

    /// Pretty print the ring buffer for debugging
    pub fn prettyPrint(self: *const RingBuffer, allocator: std.mem.Allocator) ![]u8 {
        var output = std.ArrayList(u8){};
        errdefer output.deinit(allocator);

        const Colors = struct {
            const reset = "\x1b[0m";
            const bold = "\x1b[1m";
            const dim = "\x1b[90m";
            const red = "\x1b[91m";
            const green = "\x1b[92m";
            const yellow = "\x1b[93m";
            const cyan = "\x1b[96m";
            const magenta = "\x1b[95m";
            const bright_red = "\x1b[91;1m";
            const bg_red = "\x1b[41m";
            const bg_green = "\x1b[42m";
            const black = "\x1b[30m";
        };

        try output.writer(allocator).print("\n{s}═══════════════════════════════════════════════════════════════════{s}\n", .{ Colors.bright_red, Colors.reset });
        try output.writer(allocator).print("{s}  RECENT EXECUTION HISTORY (Last {} Instructions)  {s}\n", .{ Colors.bright_red, self.count, Colors.reset });
        try output.writer(allocator).print("{s}═══════════════════════════════════════════════════════════════════{s}\n\n", .{ Colors.bright_red, Colors.reset });

        if (self.count == 0) {
            try output.writer(allocator).print("{s}  (No instructions executed yet){s}\n", .{ Colors.dim, Colors.reset });
            return output.toOwnedSlice(allocator);
        }

        try output.writer(allocator).print("{s} Step  | Sched | Opcode           | Gas Before → After    | Stack | Memory{s}\n", .{ Colors.bold, Colors.reset });
        try output.writer(allocator).print("{s}-------|-------|------------------|-----------------------|-------|--------{s}\n", .{ Colors.dim, Colors.reset });

        var ordered_buffer: [CAPACITY]Entry = undefined;
        const entries = self.getOrdered(&ordered_buffer);

        for (entries) |entry| {
            try output.writer(allocator).print("{s}{d:6}{s} | ", .{ Colors.cyan, entry.step_number, Colors.reset });
            try output.writer(allocator).print("{s}{d:5}{s} | ", .{ Colors.dim, entry.schedule_index, Colors.reset });

            const opcode_color = if (entry.is_synthetic) Colors.bg_green else Colors.yellow;
            if (entry.is_synthetic) {
                try output.writer(allocator).print("{s}{s}⚡{s:<15}{s} | ", .{ opcode_color, Colors.black, entry.opcode_name, Colors.reset });
            } else {
                try output.writer(allocator).print("{s}{s:<16}{s} | ", .{ opcode_color, entry.opcode_name, Colors.reset });
            }
            const gas_used = entry.gas_before - entry.gas_after;
            const gas_color = if (gas_used > 100) Colors.red else if (gas_used > 20) Colors.yellow else Colors.green;
            try output.writer(allocator).print("{s}{d:8} → {d:<8}{s} | ", .{ gas_color, entry.gas_before, entry.gas_after, Colors.reset });
            try output.writer(allocator).print("{s}{d:5}{s} | ", .{ Colors.dim, entry.stack_size, Colors.reset });
            try output.writer(allocator).print("{s}{d:6}{s}", .{ Colors.dim, entry.memory_size, Colors.reset });
            try output.writer(allocator).print("\n", .{});
        }

        try output.writer(allocator).print("\n", .{});
        return output.toOwnedSlice(allocator);
    }
};