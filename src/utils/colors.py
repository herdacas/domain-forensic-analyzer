"""
Terminal Colors Utility for Domain Forensic Analyzer
Professionelle Farbschemata und Formatierung fuer forensische Terminal-Ausgabe
"""

class Colors:
    """
    ANSI-Farbcodes und Formatierungs-Utilities fuer professionelle Terminal-Ausgabe
    
    Bietet ein einheitliches Farbschema fuer alle forensischen Berichte und
    stellt Hilfsmethoden fuer strukturierte Ausgabe bereit.
    """
    
    # Basis-Farbdefinitionen (ANSI Escape Codes)
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    PURPLE = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    GRAY = '\033[90m'
    
    # Formatierungs-Codes
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    DIM = '\033[2m'
    END = '\033[0m'
    
    # Hintergrund-Farben (fuer spezielle Hervorhebungen)
    BG_RED = '\033[41m'
    BG_GREEN = '\033[42m'
    BG_YELLOW = '\033[43m'
    BG_BLUE = '\033[44m'
    
    @staticmethod
    def success(text: str) -> str:
        """
        Formatiert Text als Erfolgs-Meldung (gruen)
        
        Args:
            text (str): Anzuzeigender Text
            
        Returns:
            str: Gruen formatierter Text
        """
        return f"{Colors.GREEN}{text}{Colors.END}"
    
    @staticmethod
    def error(text: str) -> str:
        """
        Formatiert Text als Fehler-Meldung (rot)
        
        Args:
            text (str): Anzuzeigender Text
            
        Returns:
            str: Rot formatierter Text
        """
        return f"{Colors.RED}{text}{Colors.END}"
    
    @staticmethod
    def warning(text: str) -> str:
        """
        Formatiert Text als Warn-Meldung (gelb)
        
        Args:
            text (str): Anzuzeigender Text
            
        Returns:
            str: Gelb formatierter Text
        """
        return f"{Colors.YELLOW}{text}{Colors.END}"
    
    @staticmethod
    def info(text: str) -> str:
        """
        Formatiert Text als Info-Meldung (blau)
        
        Args:
            text (str): Anzuzeigender Text
            
        Returns:
            str: Blau formatierter Text
        """
        return f"{Colors.BLUE}{text}{Colors.END}"
    
    @staticmethod
    def header(text: str) -> str:
        """
        Formatiert Text als Ueberschrift (fett + cyan)
        
        Args:
            text (str): Anzuzeigender Text
            
        Returns:
            str: Als Ueberschrift formatierter Text
        """
        return f"{Colors.BOLD}{Colors.CYAN}{text}{Colors.END}"
    
    @staticmethod
    def critical(text: str) -> str:
        """
        Formatiert Text als kritische Meldung (fett + rot)
        
        Args:
            text (str): Anzuzeigender Text
            
        Returns:
            str: Kritisch formatierter Text
        """
        return f"{Colors.BOLD}{Colors.RED}{text}{Colors.END}"
    
    @staticmethod
    def highlight(text: str) -> str:
        """
        Hebt Text besonders hervor (fett + weiss)
        
        Args:
            text (str): Anzuzeigender Text
            
        Returns:
            str: Hervorgehobener Text
        """
        return f"{Colors.BOLD}{Colors.WHITE}{text}{Colors.END}"
    
    @staticmethod
    def dim(text: str) -> str:
        """
        Formatiert Text gedimmt (grau)
        
        Args:
            text (str): Anzuzeigender Text
            
        Returns:
            str: Gedimmt formatierter Text
        """
        return f"{Colors.GRAY}{text}{Colors.END}"
    
    @staticmethod
    def format_ip(ip_address: str) -> str:
        """
        Spezielle Formatierung fuer IP-Adressen
        
        Args:
            ip_address (str): IP-Adresse
            
        Returns:
            str: Formatierte IP-Adresse
        """
        return f"{Colors.BOLD}{Colors.BLUE}{ip_address}{Colors.END}"
    
    @staticmethod
    def format_domain(domain: str) -> str:
        """
        Spezielle Formatierung fuer Domains
        
        Args:
            domain (str): Domain-Name
            
        Returns:
            str: Formatierte Domain
        """
        return f"{Colors.BOLD}{Colors.CYAN}{domain}{Colors.END}"
    
    @staticmethod
    def format_status(status: str, is_positive: bool = True) -> str:
        """
        Formatiert Status-Meldungen basierend auf Kontext
        
        Args:
            status (str): Status-Text
            is_positive (bool): True fuer positive, False fuer negative Status
            
        Returns:
            str: Kontextual formatierter Status
        """
        if is_positive:
            return Colors.success(status)
        else:
            return Colors.error(status)
    
    @staticmethod
    def investigation_separator(length: int = 60) -> str:
        """
        Erstellt Trennlinien fuer Investigation-Berichte
        
        Args:
            length (int): Laenge der Trennlinie
            
        Returns:
            str: Formatierte Trennlinie
        """
        return Colors.dim("=" * length)
    
    @staticmethod
    def section_header(title: str, width: int = 60) -> str:
        """
        Erstellt formatierte Sektion-Ueberschriften
        
        Args:
            title (str): Titel der Sektion
            width (int): Gesamtbreite der Ueberschrift
            
        Returns:
            str: Formatierte Sektion-Ueberschrift
        """
        padding = max(0, width - len(title) - 4)
        left_pad = padding // 2
        right_pad = padding - left_pad
        
        return Colors.header(f"[{' ' * left_pad}{title}{' ' * right_pad}]")
    
    @staticmethod
    def risk_level(level: str) -> str:
        """
        Formatiert Risk-Level basierend auf Schweregrad
        
        Args:
            level (str): Risk-Level (LOW, MEDIUM, HIGH, CRITICAL)
            
        Returns:
            str: Entsprechend formatiertes Risk-Level
        """
        level_upper = level.upper()
        
        if level_upper == "LOW":
            return Colors.success(level_upper)
        elif level_upper == "MEDIUM":
            return Colors.warning(level_upper)
        elif level_upper == "HIGH":
            return Colors.error(level_upper)
        elif level_upper == "CRITICAL":
            return Colors.critical(level_upper)
        else:
            return Colors.dim(level_upper)
    
    @staticmethod
    def is_color_supported() -> bool:
        """
        Prueft ob das Terminal Farbunterstuetzung hat
        
        Returns:
            bool: True wenn Farben unterstuetzt werden
        """
        import os
        import sys
        
        # Windows-spezifische Pruefung
        if os.name == 'nt':
            try:
                import colorama
                colorama.init()
                return True
            except ImportError:
                # Fallback: Windows 10+ hat native ANSI-Unterstuetzung
                return True
        
        # Unix/Linux-Systeme
        return hasattr(sys.stdout, 'isatty') and sys.stdout.isatty()

# Test-Funktion fuer Farb-Ausgabe und Formatierung
def main():
    """
    Test-Funktion fuer die Colors-Utility
    Demonstriert alle verfuegbaren Formatierungen und Farben
    """
    print(Colors.header("COLORS UTILITY TEST"))
    print(Colors.investigation_separator(50))
    
    # Basis-Farben testen
    print("Basis-Farben:")
    print(f"  {Colors.success('Erfolg: Gruene Meldung')}")
    print(f"  {Colors.error('Fehler: Rote Meldung')}")
    print(f"  {Colors.warning('Warnung: Gelbe Meldung')}")
    print(f"  {Colors.info('Information: Blaue Meldung')}")
    print(f"  {Colors.critical('Kritisch: Fett-Rote Meldung')}")
    print(f"  {Colors.highlight('Hervorgehoben: Fett-Weiss')}")
    print(f"  {Colors.dim('Gedimmt: Graue Meldung')}")
    
    print("\nSpezial-Formatierungen:")
    print(f"  IP-Adresse: {Colors.format_ip('192.168.1.1')}")
    print(f"  Domain: {Colors.format_domain('example.com')}")
    
    print("\nRisk-Level Formatierung:")
    for level in ["LOW", "MEDIUM", "HIGH", "CRITICAL"]:
        print(f"  Risk Level {level}: {Colors.risk_level(level)}")
    
    print("\nSektion-Header:")
    print(Colors.section_header("DNS ANALYSIS", 40))
    print(Colors.section_header("INFRASTRUCTURE", 40))
    
    print(f"\nFarbunterstuetzung: {Colors.is_color_supported()}")
    print(Colors.investigation_separator(50))

if __name__ == "__main__":
    main()