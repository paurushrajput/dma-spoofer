#[derive(Debug, Clone)]
pub struct ArpEntry {
    pub neighbor_addr: u64,
    pub interface_addr: u64,
    pub state: NeighborState,
    pub mac_address: [u8; 6],
    pub mac_addr_location: u64,
}

impl ArpEntry {
    pub fn new(
        neighbor_addr: u64,
        interface_addr: u64,
        state: NeighborState,
        mac_address: [u8; 6],
        mac_addr_location: u64,
    ) -> Self {
        Self {
            neighbor_addr,
            interface_addr,
            state,
            mac_address,
            mac_addr_location,
        }
    }

    pub fn mac_string(&self) -> String {
        format!(
            "{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
            self.mac_address[0],
            self.mac_address[1],
            self.mac_address[2],
            self.mac_address[3],
            self.mac_address[4],
            self.mac_address[5]
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum NeighborState {
    Unreachable,
    Incomplete,
    Probe,
    Delay,
    Stale,
    Reachable,
    Permanent,
    Unknown(u32),
}

impl NeighborState {
    pub fn from_raw(value: u32) -> Self {
        match value {
            0 => NeighborState::Unreachable,
            1 => NeighborState::Incomplete,
            2 => NeighborState::Probe,
            3 => NeighborState::Delay,
            4 => NeighborState::Stale,
            5 => NeighborState::Reachable,
            6 => NeighborState::Permanent,
            v => NeighborState::Unknown(v),
        }
    }

    pub fn as_str(&self) -> &str {
        match self {
            NeighborState::Unreachable => "Unreachable",
            NeighborState::Incomplete => "Incomplete",
            NeighborState::Probe => "Probe",
            NeighborState::Delay => "Delay",
            NeighborState::Stale => "Stale",
            NeighborState::Reachable => "Reachable",
            NeighborState::Permanent => "Permanent",
            NeighborState::Unknown(_) => "Unknown",
        }
    }
}

#[derive(Debug, Clone)]
pub struct Compartment {
    pub addr: u64,
    pub id: u32,
    pub neighbor_table_addr: u64,
    pub neighbor_count: u32,
}

impl Compartment {
    pub fn new(addr: u64, id: u32, neighbor_table_addr: u64, neighbor_count: u32) -> Self {
        Self {
            addr,
            id,
            neighbor_table_addr,
            neighbor_count,
        }
    }
}
