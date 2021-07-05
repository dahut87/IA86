using namespace std;
using std::cout; using std::endl;
using std::vector; using std::string;

using FKey = finalcut::FKey;
using finalcut::FPoint;
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
 
 struct i386_seg_regs 
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
         struct i386_seg_regs segs;
         struct i386_regs regs;
         uint32_t flags;
 } __attribute__ (( packed ));
 
    
class Memzone
{
    public:
        uint32_t address;
        uint32_t size;
        uint8_t *content;
};

class State {
    public:
        i386_all_regs dump;
        std::vector<Memzone> memzone;
};
    
class Goal {
    public:
        std::string title;
        std::string description;
        std::string help;
        std::string code;  
        int level;      
        State init;
        State goal;        
};

class Code
{
    public:
        uint32_t address;
        size_t size;
        unsigned char *content;
        bool assembled;
        bool executed;
        bool loaded;
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
    int getselected();
  private:
    // Method
    int selected;
    void click();
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
    std::vector<std::array<std::string, 5>> get();
    void set(std::vector<std::array<std::string, 5>> src);
  private:
    // Method
    std::vector<std::array<std::string, 5>> content;
    void initLayout() override;
    void adjustSize() override;
    // Data members
    finalcut::FListView listview{this};
};


class TextFixedWindow final : public finalcut::FDialog
{
  public:
    // Constructor
    explicit TextFixedWindow (finalcut::FWidget* = nullptr);
    // Disable copy constructor
    TextFixedWindow (const TextFixedWindow&) = delete;
    // Destructor
    ~TextFixedWindow() override = default;
    // Disable copy assignment operator (=)
    TextFixedWindow& operator = (const TextFixedWindow&) = delete;
    // Method
    std::string get();
    void set(std::string str);
  private:
    // Method
    void initLayout() override;
    void adjustSize() override;
    // Data members
    finalcut::FLabel fixedtext{this};
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
    std::string get();
    void set(std::string str);
  private:
    // Method
    void initLayout() override;
    void adjustSize() override;
    // Data members
    finalcut::FLabel fixedtext{this};
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
  private:
    // Method
    void onClose(finalcut::FCloseEvent*) override;
    void initLayout() override;
    void adjustSize() override;
    // Data members
    finalcut::FTextView scrolltext{this};
};

class Desassembler
{
  public:
    Desassembler(TextWindow *log);
    std::vector<std::array<std::string, 5>> Desassemble(Code *code);
  private:
    csh handle;
    cs_insn *insn;
    int err;
    TextWindow *log;
    TextEditWindow *edit;
    size_t srcsize;
    size_t codesize;
    std::vector<std::array<std::string, 5>> src;
    unsigned char *src_char = new unsigned char[64*1024];
};

class Assembler
{
  public:
    Assembler(TextWindow *log);
    Code *Assemble(std::string source,uint32_t address);
  private:
    ks_engine *ks;
    ks_err err;
    int err2;
    TextWindow *log;
    TextEditWindow *edit;
    Code *code = new Code;
};

class VMEngine
{
  public:
    VMEngine(TextWindow *log);
    void Configure(State *init,Code *code);
    void Run(Code *code, uint32_t start, uint32_t stop, uint64_t timeout);
    std::string getRegs(int level);
  private:
    uc_engine *uc;
    uc_err err;
    TextWindow *log;
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
    void loadGoal();
  private:
    Code *code = new Code();
    void configureFileMenuItems();
    void initMenusCallBack ();
    void initMenus();
    void initMisc();
    void initNow();
    void initCore();
    void compile();
    void exec();
    void trace();
    void step();
    void verify();
    void AdjustWindows();
    void initWindows();
    void splash();
    void initLayout() override;
    void adjustSize() override;
    // Event handler
    void onClose (finalcut::FCloseEvent*) override;
    // Callback method
    void cb_message (const finalcut::FMenuItem*);
    // Data members
    finalcut::FString        line{13, finalcut::UniChar::BoxDrawingsHorizontal};
    finalcut::FMenuBar       Menubar{this};
    finalcut::FMenu          Game{"&Partie", &Menubar};
    finalcut::FMenuItem      New{"&Nouvelle partie", &Game};
    finalcut::FMenuItem      Line2{&Game};
    finalcut::FMenuItem      Quit{"&Quitter", &Game};
    finalcut::FMenu          Options{"&Options", &Menubar};
    finalcut::FMenu          Tools{"&Outils", &Menubar};
    finalcut::FMenuItem      Assemble{"&Compilation", &Tools};
    finalcut::FMenuItem      Rearange{"&Ordonne les fenêtres", &Tools};
    finalcut::FMenu          Debug{"&Déboguage", &Menubar};
    finalcut::FMenuItem      Run{"&Exécuter", &Debug};
    finalcut::FMenuItem      End{"&Terminer", &Debug};
    finalcut::FMenuItem      TraceInto{"Pas à pas &détaillé", &Debug}; 
    finalcut::FMenuItem      StepOver{"&Pas à pas", &Debug};
    finalcut::FMenuItem      Breakpoint{"&Point d'arrêt", &Debug};
    finalcut::FDialogListMenu Window{"&Fenêtres", &Menubar};
    finalcut::FMenu          Help{"&Aide", &Menubar}; 
    finalcut::FMenuItem      About{"&A propos", &Help}; 
    finalcut::FLabel         Info{this};
    finalcut::FStatusBar     Statusbar{this};
    TextWindow               log{this};
    TextWindow               view{this};
    InstructionWindow               debug{this};
    TextFixedWindow          regs{this};
    TextFixedWindow          flags{this};
    TextFixedWindow          stack{this};
    TextFixedWindow          mem{this};
    TextFixedWindow          tuto{this};
    TextFixedWindow          screen{this};
    TextEditWindow           edit{this};
    ScenarioWindow           scenar{this};
    VMEngine                 vm{&log};
    Assembler                asmer{&log};
    Desassembler             unasmer{&log};
};

