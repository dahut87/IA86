using namespace std;
using std::cout; using std::endl;
using std::vector; using std::string;

using FKey = finalcut::FKey;
using finalcut::FColor;
using finalcut::FPoint;
using finalcut::FRect;
using finalcut::FSize;


//----------------------------------------------------------------------
// Types & classes mineures
//----------------------------------------------------------------------
 typedef union {
         struct {
                 union {
                         uint8_t l;
                         uint8_t byte;
                 };
                 uint8_t h;
         } __attribute__ (( packed ));
         uint16_t word;
 } __attribute__ (( packed )) reg16_t;
 
 typedef union {
         struct {
                 union {
                         uint8_t l;
                         uint8_t byte;
                 };
                 uint8_t h;
         } __attribute__ (( packed ));
         uint16_t word;
         uint32_t dword;
 } __attribute__ (( packed )) reg32_t;
 
 struct i386_regs {
         union {
                 uint16_t ip;
                 uint32_t eip;
         };
         union {
                 uint16_t di;
                 uint32_t edi;
         };
         union {
                 uint16_t si;
                 uint32_t esi;
         };
         union {
                 uint16_t bp;
                 uint32_t ebp;
         };
         union {
                 uint16_t sp;
                 uint32_t esp;
         };
         union {
                 struct {
                         uint8_t bl;
                         uint8_t bh;
                 } __attribute__ (( packed ));
                 uint16_t bx;
                 uint32_t ebx;
         };
         union {
                 struct {
                         uint8_t dl;
                         uint8_t dh;
                 } __attribute__ (( packed ));
                 uint16_t dx;
                 uint32_t edx;
         };
         union {
                 struct {
                         uint8_t cl;
                         uint8_t ch;
                 } __attribute__ (( packed ));
                 uint16_t cx;
                 uint32_t ecx;
         };
         union {
                 struct {
                         uint8_t al;
                         uint8_t ah;
                 } __attribute__ (( packed ));
                 uint16_t ax;
                 uint32_t eax;
         };
 } __attribute__ (( packed ));
 
 struct i386_segs 
 {
         uint16_t cs;
         uint16_t ss;
         uint16_t ds;
         uint16_t es;
         uint16_t fs;
         uint16_t gs;
 } __attribute__ (( packed ));
 
 struct i386_all_regs 
 {
         struct i386_segs segs;
         struct i386_regs regs;
         uint32_t flags;
 } __attribute__ (( packed ));

struct State {
        i386_all_regs dump;
        std::string code;
};
    
struct Level {
        std::string title;
        std::string description;
        std::string tutorial;
        std::string code;
        int rights;      
        State init;
        State goal;        
};

struct Scenario {
    std::string title;
    std::vector<Level> levels;
    bool loaded;
};

struct Code
{
        uint32_t address;
        size_t size;
        std::string name;
        uint8_t *content;
        bool assembled;
        bool loaded;
        std::string src;
};

struct Unasm
{
    std::vector<std::array<std::string, 4>> src;
    std::vector<uint32_t> pos;
};

class Error: public exception
{
public:
    Error(string const& phrase="") throw()
         :m_phrase(phrase)
    {}
 
     virtual const char* what() const throw()
     {
         return m_phrase.c_str();
     }
    
    virtual ~Error() throw()
    {}
 
private:
    string m_phrase;
};


class ScenarioWindow final : public finalcut::FDialog
{
  public:
    // Constructor
    explicit ScenarioWindow (finalcut::FWidget* = nullptr);
    // Disable copy constructor
    ScenarioWindow (const ScenarioWindow&) = delete;
    // Destructor
    ~ScenarioWindow() override = default;
    // Disable copy assignment operator (=)
    ScenarioWindow& operator = (const ScenarioWindow&) = delete;
    // Method
    void Load(std::vector<Level> items);
  private:
    // Method
    void click();
    void initLayout() override;
    void adjustSize() override;
    // Data members
    finalcut::FListView listview{this};
};

class CodeWindow final : public finalcut::FDialog
{
  public:
    // Constructor
    explicit CodeWindow (finalcut::FWidget* = nullptr);
    // Disable copy constructor
    CodeWindow (const CodeWindow&) = delete;
    // Destructor
    ~CodeWindow() override = default;
    // Disable copy assignment operator (=)
    CodeWindow& operator = (const CodeWindow&) = delete;
    // Method
    std::vector<std::array<std::string, 7>> get();
    void set(std::vector<std::array<std::string, 7>> src);
    void clear();
    int getindex();
    int getsize();
  private:
    // Method
    std::vector<std::array<std::string, 7>> content;
    void initLayout() override;
    void adjustSize() override;
    // Data members
    finalcut::FListView listview{this};
};

class InstructionWindow final : public finalcut::FDialog
{
  public:
    // Constructor
    explicit InstructionWindow (finalcut::FWidget* = nullptr);
    // Disable copy constructor
    InstructionWindow (const InstructionWindow&) = delete;
    // Destructor
    ~InstructionWindow() override = default;
    // Disable copy assignment operator (=)
    InstructionWindow& operator = (const InstructionWindow&) = delete;
    // Method
    std::vector<std::array<std::string, 4>> get();
    void set(std::vector<std::array<std::string, 4>> src);
    void clear();
    int getindex();
    void setmultimark(std::vector<int> mark);
    void setmark(int index);
    int getsize();
    std::string getaddress();
  private:
    // Method
    std::vector<std::array<std::string, 4>> content;
    void initLayout() override;
    void adjustSize() override;
    // Data members
    finalcut::FListView listview{this};
};

class TextEditWindow final : public finalcut::FDialog
{
  public:
    // Constructor
    explicit TextEditWindow (finalcut::FWidget* = nullptr);
    // Disable copy constructor
    TextEditWindow (const TextEditWindow&) = delete;
    // Destructor
    ~TextEditWindow() override = default;
    // Disable copy assignment operator (=)
    TextEditWindow& operator = (const TextEditWindow&) = delete;
    // Method
    void append(const finalcut::FString&);
    void clear();
    std::string get();
    void set(const finalcut::FString&);
  private:
    // Method
    void onClose(finalcut::FCloseEvent*) override;
    void initLayout() override;
    void adjustSize() override;
    // Data members
    finalcut::FTextView scrolltext{this};
};

class TextWindow final : public finalcut::FDialog
{
  public:
    // Constructor
    explicit TextWindow (finalcut::FWidget* = nullptr);
    // Disable copy constructor
    TextWindow (const TextWindow&) = delete;
    // Destructor
    ~TextWindow() override = default;
    // Disable copy assignment operator (=)
    TextWindow& operator = (const TextWindow&) = delete;
    // Method
    void append(const finalcut::FString&);
    void clear();
    std::string get();
    void set(const finalcut::FString&);
  private:
    // Method
    void onClose(finalcut::FCloseEvent*) override;
    void initLayout() override;
    void adjustSize() override;
    // Data members
    finalcut::FTextView scrolltext{this};
};

class Menu;

class Desassembler
{
  public:
    Desassembler(Menu *widget);
    void setSyntax(int syntax);
    void Desassemble(uint8_t *content, uint32_t address,uint32_t size, Unasm *unasm);
  private:
    csh handle;
    cs_insn *insn;
    int err;
    Menu *widget;
    TextEditWindow *edit;
    size_t srcsize;
    size_t codesize;
    std::vector<std::array<std::string, 4>> src;
    unsigned char *src_char = new unsigned char[64*1024];
};

class Assembler
{
  public:
    Assembler(Menu *widget);
    void setSyntax(int syntax);
    void Assemble(Code *code);
    std::vector<Code> MultiAssemble(std::string source,uint32_t address);
  private:
    ks_engine *ks;
    ks_err err;
    int err2;
    Menu *widget;
    TextEditWindow *edit;
};

class VMEngine
{
  public:
    VMEngine(Menu *widget);
    void Configure(State *init, std::string code);
    void Halt();
    void Unconfigure();
    uint32_t getCurrent();
    void setSyntax(int asmsyntax,int unasmsyntax);
    void Run(bool astep, bool acall, uint64_t timeout);
    std::string getFlags();
    std::string getRegs();
    std::string getStack();
    std::vector<std::array<std::string, 4>>  getInstr(int segment, int address,int size);
    std::vector<std::array<std::string, 7>> getCode();
    void SetMem(Code *code);
    void SetRegs(State *init);
    std::string getRam(int segment, int address,int lines, int linesize);
    int verify();
    bool isExecuted();
    bool isInitialized();
    void setRights(int rights);
    void clearbreakpoints();
    void addbreakpoint(uint16_t segment, uint32_t address);
    void removebreakpoint(uint16_t segment, uint32_t address);
    std::vector<int> getBreapoints();
    int getLine();
    uint32_t getEIP();
    uint32_t getESI();
    uint32_t getEDI();
    uint32_t getESP();
    uint32_t getEBP();
    uint16_t getCS();
    uint16_t getDS();
    uint16_t getES();
    uint16_t getSS();
  private:
    int rights;
    void Init();
    void Close();
    uc_engine *uc;
    uc_err err;
    int bufferaddress;
    int address_old;
    uint8_t *code;
    uLong crc,crc_old;
    std::vector<Code> mcode;
    Menu *widget;
    Assembler asmer{widget};
    Desassembler unasmer{widget};
};

class Menu final : public finalcut::FDialog
{
  public:
    // Constructor
    explicit Menu (finalcut::FWidget* = nullptr);
    // Disable copy constructor
    Menu (const Menu&) = delete;
    // Destructor
    ~Menu() override = default;
    // Disable copy assignment operator (=)
    Menu& operator = (const Menu&) = delete;
     // Methods
    void loadLevel(int alevel);
    void closeLevel();
    void tolog(std::string str);
    std::vector<std::array<std::string, 4>> getsrc();
    void SetScreen(uint16_t x, uint16_t y, char value);
  private:
    void onTimer (finalcut::FTimerEvent*) override;
    void refresh();
    void configureFileMenuItems();
    void initMenusCallBack ();
    void initMenus();
    void initMisc();
    void compile();
    void end();
    void loadScenario(std::string file);
    void showInstr();
    void addbp();
    void exec();
    void trace();
    void step();
    void about();
    void changesyntax();
    void ClearScreen();
    void AdjustWindows();
    void initWindows();
    void openscenar();
    void closescenar();
    void initLayout() override;
    // Event handler
    void onClose (finalcut::FCloseEvent*) override;
    // Callback method
    void cb_message (const finalcut::FMenuItem*);
    // Data members
    //finalcut::FString        line{13, finalcut::UniChar::BoxDrawingsHorizontal};
    finalcut::FMenuBar       Menubar{this};
    finalcut::FMenu          Game{"&Partie", &Menubar};
    finalcut::FMenuItem      New{"&Nouvelle partie", &Game};
    finalcut::FMenuItem      Open{"&Ouvrir une partie", &Game};
    finalcut::FMenuItem      Save{"&Sauver la partie", &Game};
    finalcut::FMenuItem      Close{"&Fermer une partie", &Game};
    finalcut::FMenuItem      Line2{&Game};
    finalcut::FMenuItem      OpenScenar{"&Ouvrir un sc??nario", &Game};
    finalcut::FMenuItem      CloseScenar{"&Fermer un sc??nario", &Game};    
    finalcut::FMenuItem      Line3{&Game};
    finalcut::FMenuItem      Quit{"&Quitter", &Game};
    finalcut::FMenu          Views{"&vues", &Menubar};
    finalcut::FRadioMenuItem Rearange1{"&Sc??narios", &Views};
    finalcut::FRadioMenuItem Rearange3{"&Objectifs", &Views};
    finalcut::FRadioMenuItem Rearange{"&Deboguage", &Views};
    finalcut::FRadioMenuItem Rearange2{"&Donn??es", &Views};    
    finalcut::FMenu          Tools{"&Outils", &Menubar};
    finalcut::FMenuItem      Assemble{"&Assembler", &Tools};
    finalcut::FMenu          Debug{"&Ex??cution", &Menubar};
    finalcut::FMenuItem      Run{"&Ex??cuter", &Debug};
    finalcut::FMenuItem      End{"&Terminer", &Debug};
    finalcut::FMenuItem      TraceInto{"Pas ?? pas &d??taill??", &Debug}; 
    finalcut::FMenuItem      StepOver{"&Pas ?? pas", &Debug};
    finalcut::FMenu          Breakpoint{"&Point d'arr??t", &Menubar};
    finalcut::FMenuItem      AddBp{"&Ajouter", &Breakpoint};
    finalcut::FMenuItem      ClearBp{"&Supprimer", &Breakpoint};
    finalcut::FMenuItem      ClearAllBp{"&Tout supprimer", &Breakpoint};
    finalcut::FMenu          Options{"&Options", &Menubar};
    finalcut::FMenu          Memory{"&Visualisateur M??moire", &Options};
    finalcut::FRadioMenuItem Ds_000{"DS:0000", &Memory};
    finalcut::FRadioMenuItem Ds_esi{"DS:ESI", &Memory};
    finalcut::FRadioMenuItem Es_edi{"ES:EDI", &Memory};
    finalcut::FRadioMenuItem Cs_eip{"CS:EIP", &Memory};
    finalcut::FRadioMenuItem Ss_esp{"SS:ESP", &Memory};
    finalcut::FRadioMenuItem Ss_FFF{"SS:FFFF", &Memory};
    finalcut::FRadioMenuItem Value{"Valeur...", &Memory};
    finalcut::FMenu          Code{"&Syntaxe", &Options};
    finalcut::FCheckMenuItem AsmAtt{"Assembleur AT&T", &Code};
    finalcut::FCheckMenuItem UnasmAtt{"D??sassembleur AT&T", &Code};
    finalcut::FDialogListMenu Window{"&Fen??tres", &Menubar};
    finalcut::FMenu          Help{"&Aide", &Menubar}; 
    finalcut::FMenuItem      About{"&A propos", &Help}; 
    finalcut::FTextView      Log{this};
    finalcut::FStatusBar     Statusbar{this};
    TextWindow               info{this};
    TextWindow               view{this};
    InstructionWindow        debug{this};
    CodeWindow               codes{this};
    TextWindow               regs{this};
    TextWindow               flags{this};
    TextWindow               stack{this};
    TextWindow               mem{this};
    TextWindow               tuto{this};
    TextWindow               screen{this};
    TextEditWindow           edit{this};
    ScenarioWindow           scenar{this};
    VMEngine                 vm{this};
};
