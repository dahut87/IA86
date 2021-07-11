#include <final/final.h>
#include <unistd.h>
#include <regex>
#include <iostream>
#include <sstream>
#include <string>
#include <sstream>
#include <iomanip>
#include <keystone/keystone.h>
#include <unicorn/unicorn.h>
#include <capstone/capstone.h>
#include <vector>
#include <zlib.h>
#include "ia86.h"
#include <exception>
#include "struct_mapping/struct_mapping.h"



//----------------------------------------------------------------------
// Fonctions diverses
//----------------------------------------------------------------------

std::string intToHexString(int intValue, int size) {
    string hexStr;
    std::stringstream sstream;
    sstream << std::uppercase << std::setfill ('0') << std::setw(size) << std::hex << (int)intValue;
    hexStr= sstream.str();
    sstream.clear();
    return hexStr;
}

void mapping()
{
    struct_mapping::reg(&Scenario::title, "scenario_titre");
    struct_mapping::reg(&Scenario::levels, "scenario_objectifs");
    struct_mapping::reg(&Level::title, "niveau_titre");
    struct_mapping::reg(&Level::description, "niveau_description");
    struct_mapping::reg(&Level::tutorial, "niveau_tutoriel");
    struct_mapping::reg(&Level::code, "niveau_code");
    struct_mapping::reg(&Level::rights, "niveau_droits");
    struct_mapping::reg(&Level::init, "niveau_initial");
    struct_mapping::reg(&Level::goal, "niveau_objectif");
    struct_mapping::reg(&State::dump, "registres");
    struct_mapping::reg(&State::code, "code");
    struct_mapping::reg(&i386_all_regs::segs, "segments");
    struct_mapping::reg(&i386_all_regs::regs, "généraux");
    struct_mapping::reg(&i386_all_regs::flags, "drapeaux");
    struct_mapping::reg(&i386_segs::cs, "cs");
    struct_mapping::reg(&i386_segs::ss, "ss");
    struct_mapping::reg(&i386_segs::ds, "ds");
    struct_mapping::reg(&i386_segs::es, "es");
    struct_mapping::reg(&i386_segs::fs, "fs");
    struct_mapping::reg(&i386_segs::gs, "gs");
    struct_mapping::reg(&i386_regs::eax, "eax");
    struct_mapping::reg(&i386_regs::ebx, "ebx");
    struct_mapping::reg(&i386_regs::ecx, "ecx");
    struct_mapping::reg(&i386_regs::edx, "edx");
    struct_mapping::reg(&i386_regs::esi, "esi");
    struct_mapping::reg(&i386_regs::edi, "edi");
    struct_mapping::reg(&i386_regs::esp, "esp");
    struct_mapping::reg(&i386_regs::ebp, "ebp");
    struct_mapping::reg(&i386_regs::eip, "eip"); 
}

Scenario readscenario(std::string filename) {
   
    std::ifstream inFile;
    inFile.open(filename);
    std::stringstream strStream;
    strStream << inFile.rdbuf();
    std::string json=strStream.str();
    std::istringstream json_data(json);
    Scenario scenar;
    struct_mapping::map_json_to_struct(scenar, json_data);
    return scenar;
}

Scenario scenario;
Unasm unasm;
int marker;
bool debug=true;
//----------------------------------------------------------------------
// Classe ScenarioWindow
//----------------------------------------------------------------------

ScenarioWindow::ScenarioWindow (finalcut::FWidget* parent)
  : finalcut::FDialog{parent}
{
  listview.ignorePadding();
  listview.addColumn ("*");
  listview.addColumn ("Intitulé");  
  listview.hideSortIndicator(true);
  listview.setFocus();
  listview.addCallback
  (
    "row-changed",
    this, &ScenarioWindow::click
  );
}

bool ScenarioWindow::load(std::string file)
{
   scenario=readscenario(file);
   if (scenario.levels.size()>0) 
    {
        std::vector<std::string> items;
      for(size_t i=0; i < scenario.levels.size(); i++)
      {
        //((Menu*)this->getParent())->log.append(".");
        items.clear();
        items.push_back(to_string(i));
        items.push_back(scenario.levels[i].title);
        const finalcut::FStringList line (items.begin(), items.end());    
        listview.insert (line);
      }
      return true;
    }
    else
        return false;
}

void ScenarioWindow::click()
{
    selected=listview.getindex();
    ((Menu*)this->getParent())->loadLevel();
}

int ScenarioWindow::getselected()
{
    return selected;
}

void ScenarioWindow::initLayout()
{
  listview.setGeometry (FPoint{1, 2}, FSize{getWidth(), getHeight() - 1});
  FDialog::initLayout();
}

void ScenarioWindow::adjustSize()
{
  finalcut::FDialog::adjustSize();
  listview.setGeometry (FPoint{1, 2}, FSize(getWidth(), getHeight() - 1));
}


//----------------------------------------------------------------------
// Classe InstructionWindow
//----------------------------------------------------------------------

InstructionWindow::InstructionWindow (finalcut::FWidget* parent)
  : finalcut::FDialog{parent}
{

  listview.ignorePadding();
  listview.addColumn ("P");
  listview.addColumn ("Adresse");
  listview.addColumn ("Opcodes     ");
  listview.addColumn ("Mnémo.");
  listview.addColumn ("Opérandes");
  listview.hideSortIndicator(true);
  listview.setFocus();
}

std::vector<std::array<std::string, 5>> InstructionWindow::get()
{
    return content;
}

void InstructionWindow::clear()
{
  listview.clear();
  listview.redraw();
}

void InstructionWindow::setmark(int index)
{
  listview.setmark(index);
}

int InstructionWindow::getsize()
{
  return listview.getCount();
}

void InstructionWindow::set(std::vector<std::array<std::string, 5>> src)
{
  content=src;
  listview.clear();
  for (const auto& place : content)
  {
    const finalcut::FStringList line (place.begin(), place.end());
    listview.insert (line);
  }
  listview.redraw();
}

void InstructionWindow::initLayout()
{
  listview.setGeometry (FPoint{1, 2}, FSize{getWidth(), getHeight() - 1});
  setMinimumSize (FSize{51, 6});
  FDialog::initLayout();
}

void InstructionWindow::adjustSize()
{
  finalcut::FDialog::adjustSize();
  listview.setGeometry (FPoint{1, 2}, FSize(getWidth(), getHeight() - 1));
}    

//----------------------------------------------------------------------
// Classe TextEditWindow
//----------------------------------------------------------------------

TextEditWindow::TextEditWindow (finalcut::FWidget* parent)
  : finalcut::FDialog{parent}
{
  scrolltext.ignorePadding();
  scrolltext.setFocus();
}

void TextEditWindow::onClose(finalcut::FCloseEvent*) 
{
  return;    
}

void TextEditWindow::append(const finalcut::FString& str)
{
  scrolltext.append(str);
  scrolltext.scrollBy (0, 10);
}

std::string TextEditWindow::get()
{
  return scrolltext.getText().toString () ;
}

void TextEditWindow::set(const finalcut::FString& str)
{
  scrolltext.clear(); 
  scrolltext.append(str);
  scrolltext.redraw();
}

void TextEditWindow::clear()
{
  scrolltext.clear();
}


void TextEditWindow::initLayout()
{
  scrolltext.setGeometry (FPoint{1, 2}, FSize{getWidth(), getHeight() - 1});
  FDialog::initLayout();
}

void TextEditWindow::adjustSize()
{
  finalcut::FDialog::adjustSize();
  scrolltext.setGeometry (FPoint{1, 2}, FSize(getWidth(), getHeight() - 1));
}

//----------------------------------------------------------------------
// Classe TextWindow
//----------------------------------------------------------------------

TextWindow::TextWindow (finalcut::FWidget* parent)
  : finalcut::FDialog{parent}
{
  scrolltext.ignorePadding();
  scrolltext.setFocus();
}

void TextWindow::onClose(finalcut::FCloseEvent*) 
{
  return;    
}

void TextWindow::append(const finalcut::FString& str)
{
  scrolltext.append(str);
  scrolltext.scrollBy (0, 10);
}

std::string TextWindow::get()
{
  return scrolltext.getText().toString () ;
}

void TextWindow::set(const finalcut::FString& str)
{
  scrolltext.clear(); 
  scrolltext.append(str);
  scrolltext.redraw();
}

void TextWindow::clear()
{
  scrolltext.clear();
}


void TextWindow::initLayout()
{
  scrolltext.setGeometry (FPoint{1, 2}, FSize{getWidth(), getHeight() - 1});
  FDialog::initLayout();
}

void TextWindow::adjustSize()
{
  finalcut::FDialog::adjustSize();
  scrolltext.setGeometry (FPoint{1, 2}, FSize(getWidth(), getHeight() - 1));
}

//----------------------------------------------------------------------
// Classe Desassembler
//----------------------------------------------------------------------

Desassembler::Desassembler(TextWindow *log) : log(log)
{
    try
    {
        err = cs_open(CS_ARCH_X86, CS_MODE_16, &handle);
        if (err != CS_ERR_OK) 
            throw Error("Désassembleur - initialisation....................[ERREUR]");
        log->append("Désassembleur - initialisation....................[  OK  ]");
    }
    catch(exception const& e)
    {
       log->append(e.what());
    }
}

void Desassembler::Desassemble(uint8_t *content, uint32_t address,uint32_t size, Unasm *unasm)
{
    try
    {
        srcsize=cs_disasm(handle, content, size, address, 0, &insn);
        if (srcsize == 0)
            throw Error("Désassembleur - désassemblage.....................[ERREUR]");
        else
        {  
            if (debug) log->append("Désassemblage - désassemblage.....................[ "+to_string(srcsize)+"l ]");
            unasm->src.clear();
            unasm->pos.clear();
		    for (size_t j = 0; j < srcsize; j++)
		    {
		        std::string *bytes = new std::string("");
		        for (size_t k = 0; k < insn[j].size; k++)
                    *bytes=*bytes+intToHexString((int)insn[j].bytes[k], 2);
                std::string adresse = intToHexString((int)insn[j].address, 8);  
		        std::string *menmonic = new std::string((char *)insn[j].mnemonic);
		        std::string *op_str = new std::string((char *)insn[j].op_str);
		        std::array<std::string, 5> *array = new  std::array<std::string, 5>{"", adresse, *bytes, *menmonic, *op_str};
		        unasm->src.push_back(*array);
		        unasm->pos.push_back(insn[j].address);
            }
		    cs_free(insn, srcsize);
        }
    }
    catch(exception const& e)
    {
       unasm->src.clear();
       unasm->pos.clear();
       log->append(e.what());
    }

}

//----------------------------------------------------------------------
// Classe Assembler
//----------------------------------------------------------------------

Assembler::Assembler(TextWindow *log) : log(log)
{
    try
    {
        err = ks_open(KS_ARCH_X86, KS_MODE_16, &ks);
        if (err != KS_ERR_OK) 
            throw Error("Assembleur - initialisation.......................[ERREUR]");
        log->append("Assembleur - initialisation.......................[  OK  ]");
    }
    catch(exception const& e)
    {
       log->append(e.what());
    }
}

std::vector<Code> Assembler::MultiAssemble(std::string source,uint32_t address)
{
    try
    {
        std::vector<Code> mcode;
        std::istringstream stream(source);
        std::string line;
        std::regex regex("^ *.org 0x([0-F]+)$");
        Code *code=new Code;
        bool begin=true;
        int org=address;
        code->address=org;
        while (std::getline(stream, line)) 
        {
            if (line.find(".org") != std::string::npos)
            {
                std::smatch match;
                if(std::regex_search(line, match, regex))
                {
                    org=std::stoul(match.str(1), nullptr, 16);
                }
                if (!begin)
                {
                    mcode.push_back(*code);
                    code=new Code;
                    code->address=org;                
                }
            }    
            else
            {
                code->src.append(line+"\n");
            }
            begin=false;
        }
        if (code->src.size()>0)
            mcode.push_back(*code);
        for(size_t i=0;i<mcode.size();i++)
            this->Assemble(&mcode[i]);
        log->append("Assembleur - assemblage...........................[  OK  ]");
        return mcode;
     }
    catch(exception const& e)
    {
       std::vector<Code> mcode;
       log->append(e.what());
       return mcode;
    }

}

void Assembler::Assemble(Code *code)
{
    size_t srcsize=code->src.size();
    unsigned char src_char[srcsize+1];
    strcpy(reinterpret_cast<char*>(src_char), code->src.c_str());
    err2=ks_asm(ks, reinterpret_cast<const char*>(src_char), code->address, &code->content, &code->size, &srcsize);
    if (err2 != KS_ERR_OK)
    {
        code->size=0;
        code->assembled=false;
        code->loaded=false;
        throw Error("Assembleur - assemblage...........................[ERREUR]");
    }
    else
        code->assembled=true;
}
 
//----------------------------------------------------------------------
// Classe VMEngine
//----------------------------------------------------------------------

VMEngine::VMEngine(TextWindow *log) : log(log)
{
    code=new uint8_t[500];
    Init();
}
// Level  1 : IP AL
// Level  2 : IP AX
// Level  3 : IP AX BX CX DX
// Level  4 : IP AX BX CX DX FLAGS
// Level  5 : IP AX BX CX DX FLAGS SI DI
// Level  6 : IP AX BX CX DX FLAGS SI DI SP BP
// Level  7 : IP AX BX CX DX FLAGS SI DI SP BP CS DS ES SS
// Level  8 : IP AX BX CX DX FLAGS SI DI SP BP CS DS ES SS FS GS
// Level  9 : EIP EAX EBX ECX EDX EFLAGS ESI EDI ESP EBP CS DS ES SS FS GS
// Level 10 : EIP EAX EBX ECX EDX EFLAGS ESI EDI ESP EBP CS DS ES SS FS GS ST0 ST1 ST2 ST3 ST4 ST5 ST6 ST7
// Level 11 : EIP EAX EBX ECX EDX EFLAGS ESI EDI ESP EBP CS DS ES SS FS GS ST0 ST1 ST2 ST3 ST4 ST5 ST6 ST7 CR0 CR2 CR3 CR4 CR8 
// Level 12 : EIP EAX EBX ECX EDX EFLAGS ESI EDI ESP EBP CS DS ES SS FS GS ST0 ST1 ST2 ST3 ST4 ST5 ST6 ST7 CR0 CR2 CR3 CR4 CR8 DB0 DB1 DB2 DB3 DB6 DB7
std::string VMEngine::getFlags()
{
        int eflags=0;
        err = uc_reg_read(uc, UC_X86_REG_EFLAGS, &eflags);
        if (err != UC_ERR_OK)
            throw Error("VM IA86 - voir EFLAGS.............................[ERREUR]");
        std::stringstream out;
        out << "  CF:" << std::dec << ((eflags & 0x0001));
        if (rights > 8) 
            out << "  RF:" << std::dec << ((eflags & 0x00010000)>>16) << "\n";
        else
            out << "\n"; 
        out << "  PF:" << std::dec << ((eflags & 0x0004)>>2); 
        if (rights > 8)
            out << "  VM:" << std::dec << ((eflags & 0x00020000)>>17) << "\n";
        else
            out << "\n";
        out << "  AF:" << std::dec << ((eflags & 0x0010)>>4);    
        if (rights > 8)
            out << "  AC:" << std::dec << ((eflags & 0x00040000)>>18) << "\n";
        else
            out << "\n";
        out << "  ZF:" << std::dec << ((eflags & 0x0040)>>6);
        if (rights > 8)
            out << " VIF:" << std::dec << ((eflags & 0x00080000)>>19) << "\n";
        else
            out << "\n";
        out << "  SF:" << std::dec << ((eflags & 0x0080)>>7);
        if (rights > 8)
            out << " VIP:" << std::dec << ((eflags & 0x00100000)>>20) << "\n";      
        else
            out << "\n";
        out << "  TF:" << std::dec << ((eflags & 0x0100)>>8);
        if (rights > 8)
            out << "  ID:" << std::dec << ((eflags & 0x00200000)>>21) << "\n";
        else
            out << "\n";
        out << "  IF:" << std::dec << ((eflags & 0x0200)>>9) << "\n";        
        out << "  DF:" << std::dec << ((eflags & 0x0400)>>10) << "\n";        
        out << "  OF:" << std::dec << ((eflags & 0x0800)>>11) << "\n";        
        out << "IOPL:" << std::dec << ((eflags & 0x3000)>>12) << "\n";        
        out << "  NT:" << std::dec << ((eflags & 0x4000)>>13) << "\n";    
        return out.str();    
}

std::string VMEngine::getRegs()
{
    int regsi836[] = {
        UC_X86_REG_EAX, UC_X86_REG_EBX, UC_X86_REG_ECX, UC_X86_REG_EDX, 
        UC_X86_REG_ESI, UC_X86_REG_EDI, 
        UC_X86_REG_EBP, UC_X86_REG_ESP, 
        UC_X86_REG_CS,UC_X86_REG_DS,UC_X86_REG_ES,UC_X86_REG_SS,UC_X86_REG_FS,UC_X86_REG_GS,
        UC_X86_REG_EIP,UC_X86_REG_EFLAGS
    };
    void *ptrs[sizeof(regsi836)];
    uint32_t vals[sizeof(regsi836)];
    for (size_t i = 0; i < sizeof(regsi836); i++) {
        ptrs[i] = &vals[i];
    }
    err = uc_reg_read_batch(uc, regsi836, ptrs, sizeof(regsi836));
    if (err > 0) {
        throw Error("VM IA86 - voir REGISTRES..........................[ERREUR]");
        return "";
    }
    std::stringstream out;
    if (rights > 8)
        out << "EAX:" << std::uppercase << std::setfill('0') << std::setw(8) << std::hex << vals[0] << " | ";
    if (rights > 1)
        out << "AX:" << std::uppercase << std::setfill('0') << std::setw(4) << std::hex << (vals[0] & 0x0000FFFF) << " | "; 
    if (rights > 1)
        out << "AH:" << std::uppercase << std::setfill('0') << std::setw(2) << std::hex << ((vals[0] & 0xFF00) >> 8) << " | "; 
    out << "AL:" << std::uppercase << std::setfill('0') << std::setw(2) << std::hex << (vals[0] & 0xFF) << "\n"; 

    if (rights > 8)
        out << "EBX:" << std::uppercase << std::setfill('0') << std::setw(8) << std::hex << vals[1] << " | ";
    if (rights > 2)
        out << "BX:" << std::uppercase << std::setfill('0') << std::setw(4) << std::hex << (vals[1] & 0x0000FFFF) << " | "; 
    if (rights > 2)
        out << "BH:" << std::uppercase << std::setfill('0') << std::setw(2) << std::hex << ((vals[1] & 0xFF00) >> 8) << " | "; 
    if (rights > 2)
        out << "BL:" << std::uppercase << std::setfill('0') << std::setw(2) << std::hex << (vals[1] & 0xFF) << "\n"; 
    
    if (rights > 8)
        out << "ECX:" << std::uppercase << std::setfill('0') << std::setw(8) << std::hex << vals[2] << " | ";
    if (rights > 2)
        out << "CX:" << std::uppercase << std::setfill('0') << std::setw(4) << std::hex << (vals[2] & 0x0000FFFF) << " | "; 
    if (rights > 2)
        out << "CH:" << std::uppercase << std::setfill('0') << std::setw(2) << std::hex << ((vals[2] & 0xFF00) >> 8) << " | "; 
    if (rights > 2)
        out << "CL:" << std::uppercase << std::setfill('0') << std::setw(2) << std::hex << (vals[2] & 0xFF) << "\n"; 
    
    if (rights > 8)
        out << "EDX:" << std::uppercase << std::setfill('0') << std::setw(8) << std::hex << vals[3] << " | ";
    if (rights > 2)
        out << "DX:" << std::uppercase << std::setfill('0') << std::setw(4) << std::hex << (vals[3] & 0x0000FFFF) << " | "; 
    if (rights > 2)
        out << "DH:" << std::uppercase << std::setfill('0') << std::setw(2) << std::hex << ((vals[3] & 0xFF00) >> 8) << " | "; 
    if (rights > 2)
        out << "DL:" << std::uppercase << std::setfill('0') << std::setw(2) << std::hex << (vals[3] & 0xFF) << "\n"; 
    
    if (rights > 8)
        out << "ESI:" << std::uppercase << std::setfill('0') << std::setw(8) << std::hex << vals[4] << " | ";
    if (rights > 4)    
        out << "SI:" << std::uppercase << std::setfill('0') << std::setw(4) << std::hex << (vals[4] & 0x0000FFFF) << "\n"; 
    if (rights > 8)
        out << "EDI:" << std::uppercase << std::setfill('0') << std::setw(8) << std::hex << vals[5] << " | ";
    if (rights > 4)
        out << "DI:" << std::uppercase << std::setfill('0') << std::setw(4) << std::hex << (vals[5] & 0x0000FFFF) << "\n";
    
    if (rights > 8)
        out << "EBP:" << std::uppercase << std::setfill('0') << std::setw(8) << std::hex << vals[6] << " | ";
    if (rights > 5)
        out << "BP:" << std::uppercase << std::setfill('0') << std::setw(4) << std::hex << (vals[6] & 0x0000FFFF) << "\n"; 
    if (rights > 8)
        out << "ESP:" << std::uppercase << std::setfill('0') << std::setw(8) << std::hex << vals[7] << " | ";
    if (rights > 5)
        out << "SP:" << std::uppercase << std::setfill('0') << std::setw(4) << std::hex << (vals[7] & 0x0000FFFF) << "\n";
    
    if (rights > 6)
        out << "CS:" << std::uppercase << std::setfill('0') << std::setw(4) << std::hex << (vals[8] & 0x0000FFFF) << " | "; 
    if (rights > 6)
        out << "DS:" << std::uppercase << std::setfill('0') << std::setw(4) << std::hex << (vals[9] & 0x0000FFFF) << " | "; 
    if (rights > 6)
        out << "ES:" << std::uppercase << std::setfill('0') << std::setw(4) << std::hex << (vals[10] & 0x0000FFFF) << "\n"; 
    if (rights > 6)
        out << "SS:" << std::uppercase << std::setfill('0') << std::setw(4) << std::hex << (vals[11] & 0x0000FFFF) << " | "; 
    if (rights > 7)
        out << "FS:" << std::uppercase << std::setfill('0') << std::setw(4) << std::hex << (vals[12] & 0x0000FFFF) << " | ";
    if (rights > 7) 
        out << "GS:" << std::uppercase << std::setfill('0') << std::setw(4) << std::hex << (vals[13] & 0x0000FFFF) << "\n"; 
    
    if (rights > 8)
        out << "EIP:" << std::uppercase << std::setfill('0') << std::setw(8) << std::hex << vals[14] << " | ";
    out << "IP:" << std::uppercase << std::setfill('0') << std::setw(4) << std::hex << (vals[14] & 0x0000FFFF) << "\n";
    
    if (rights > 3)
    if (rights < 9)
        out << "FLAGS:" << std::uppercase << std::setfill('0') << std::setw(8) << std::hex << (vals[15]  & 0xFFFF)<< ""; 
    else
        out << "EFLAGS:" << std::uppercase << std::setfill('0') << std::setw(8) << std::hex << vals[15] << ""; 
    return out.str();
}

void VMEngine::Init()
{
    try
    {
        err = uc_open(UC_ARCH_X86, UC_MODE_16, &uc);
        if (err != UC_ERR_OK)
            throw Error("VM IA86 - initilisation...........................[ERREUR]");
        log->append("VM IA86 - initilisation...........................[  OK  ]");
    }
    catch(exception const& e)
    {
        log->append(e.what());
    }
}

bool VMEngine::isExecuted()
{
    return this->executed;
}

bool VMEngine::isInitialized()
{
    return this->initialized;
}

void VMEngine::Close()
{
   uc_close(uc);
}

void VMEngine::Halt()
{
    if (this->executed)
        log->append("VM IA86 - arret...................................[ INFO ]");
   this->executed=false;
}

void VMEngine::Unconfigure()
{
   this->Halt();
    if (this->initialized)
        log->append("VM IA86 - déconfiguration.........................[ INFO ]");
   this->initialized=false;
}

uint32_t VMEngine::getNextInstr()
{
    uint32_t now=getEIP();
    bool flag=false;
    for(int pos: unasm.pos)
    {
       if (pos==now)
          flag=true;
       else if (flag)
          return pos;
    }
    return 0;
}

std::vector<std::array<std::string, 5>> VMEngine::getInstr(int segment, int address,int size)
{   
    uint32_t realaddress=segment*16+address;
    if (realaddress<bufferaddress || realaddress+(size*7)>bufferaddress+500)
    {
    log->append("read");
        bufferaddress=realaddress-30;
        if (bufferaddress<0) 
            bufferaddress=0x00000000;
        address_old=address-30;
        if (address_old<0) 
            address_old=0x00000000;
    }
    err = uc_mem_read(uc, bufferaddress, code, 500);
    if (err) 
        throw Error("VM IA86 - cache instructions......................[ERREUR]");
    crc = crc32(0,  code, 500);
    if (crc != crc_old)
    {
     log->append("unasm");
        unasmer.Desassemble(code, address_old, 500, &unasm);
        if (unasm.src.size()==0)
            throw Error("VM IA86 - cache instructions......................[ERREUR]");
        crc_old=crc;
    }    
    int line=0;
    for(int pos: unasm.pos)
    {
       if (pos==address)
            break;
       line++;
    }  
    int first=line-((int)size/2);
    if (first<0) first=0;
    int last=first+size;
    marker=0;
    std::string reference=intToHexString(address, 8);
    std::vector<std::array<std::string, 5>> result = {unasm.src.begin()+first,unasm.src.begin()+last};
    for(std::array<std::string, 5> item: result)
    {
        if (item[1]==reference)
            break;
        marker++;
    }
    return result;
}


int VMEngine::getLine()
{
    return marker;
}

void VMEngine::Configure(State *init, std::string code)
{
    try
    {
        int status;
        mcode.clear();
        mcode=asmer.MultiAssemble(code,init->dump.regs.eip);
        if (mcode.size()==0)
            return;
        Close();
        Init();
        bufferaddress=-666;
        this->initialized=false;
        this->executed=false;
        //log->append("Mappage de la mémoire virtuelle");
        uc_mem_map(uc, 0, 1 * 1024 * 1024, UC_PROT_ALL);
        for(size_t i=0;i<mcode.size();i++)
        {
           if (mcode[i].assembled) 
                SetMem(&mcode[i]);
           else     
                throw Error("VM IA86 - code non assemblé...................[ERREUR]");
           if (debug) log->append("Section N°"+std::to_string(i)+" : "+intToHexString(mcode[i].address,8)+" -> "+to_string(mcode[i].size)+" octets");
        }
        status=verify();
        if (status==0)
        {
            this->initialized=true;
            SetRegs(init);   
        }
        else
            this->initialized=false;
    }
    catch(exception const& e)
    {
        log->append(e.what());
        this->initialized=false;
    }
}

int VMEngine::verify()
{
   for(Code code: mcode)
   {
      if (!code.assembled)
        return 1;
      else if (!code.loaded)
         return 2;       
   }
   return 0;
}

void VMEngine::setRights(int rights)
{
    this->rights=rights;
}

uint32_t VMEngine::getCurrent()
{
    return getEIP()+getCS()*16;
}

uint32_t VMEngine::getEIP()
{
        int eip;
        err = uc_reg_read(uc, UC_X86_REG_EIP, &eip);
        if (err != UC_ERR_OK)
           throw Error("VM IA86 - voir EIP................................[ERREUR]");
        return eip;
}

uint16_t VMEngine::getCS()
{
        int cs;
        err = uc_reg_read(uc, UC_X86_REG_CS, &cs);
        if (err != UC_ERR_OK)
           throw Error("VM IA86 - voir CS.................................[ERREUR]");
        return cs;
}

uint16_t VMEngine::getDS()
{
        int ds;
        err = uc_reg_read(uc, UC_X86_REG_DS, &ds);
        if (err != UC_ERR_OK)
           throw Error("VM IA86 - voir DS.................................[ERREUR]");
        return ds;
}

uint16_t VMEngine::getES()
{
        int es;
        err = uc_reg_read(uc, UC_X86_REG_ES, &es);
        if (err != UC_ERR_OK)
           throw Error("VM IA86 - voir ES.................................[ERREUR]");
        return es;
}

uint16_t VMEngine::getSS()
{
        int ss;
        err = uc_reg_read(uc, UC_X86_REG_SS, &ss);
        if (err != UC_ERR_OK)
           throw Error("VM IA86 - voir SS.................................[ERREUR]");
        return ss;
}

void VMEngine::SetMem(Code *code)
{

        err = uc_mem_write(uc, code->address, code->content, code->size);
        if (err) 
        {
            code->loaded=false;
            throw Error("VM IA86 - copie mémoire...........................[ERREUR]");
            return;
        }
        code->loaded=true;
}
 
void VMEngine::SetRegs(State *init)
{
        std::stringstream out;
        out << "VM IA86 - configuration initiale..................[  OK  ]"; 
        err = uc_reg_write(uc, UC_X86_REG_EIP, &init->dump.regs.eip);
        if (err != UC_ERR_OK)
           throw Error("VM IA86 - configuration initiale EIP..............[ERREUR]");
        else
        if (init->dump.regs.eip != 0x00000000)
            if ((init->dump.regs.eip & 0xFFFF0000) == 0x00000000)
                out << " IP=" << std::uppercase << std::setfill('0') << std::setw(4) << std::hex << init->dump.regs.ip << " ";               
            else
                out << "EIP=" << std::uppercase << std::setfill('0') << std::setw(8) << std::hex << init->dump.regs.eip << " ";     
        err = uc_reg_write(uc, UC_X86_REG_EDI, &init->dump.regs.edi);
        if (err != UC_ERR_OK)
           throw Error("VM IA86 - configuration initiale EDI..............[ERREUR]");
        else
        if (init->dump.regs.edi != 0x00000000)
            if ((init->dump.regs.edi & 0xFFFF0000) == 0x00000000)
                out << " DI=" << std::uppercase << std::setfill('0') << std::setw(4) << std::hex << init->dump.regs.di << " ";               
            else
                out << "EDI=" << std::uppercase << std::setfill('0') << std::setw(8) << std::hex << init->dump.regs.edi << " ";               
        err = uc_reg_write(uc, UC_X86_REG_ESI, &init->dump.regs.esi);
        if (err != UC_ERR_OK)
           throw Error("VM IA86 - configuration initiale ESI..............[ERREUR]");
        else
        if (init->dump.regs.esi != 0x00000000)
            if ((init->dump.regs.esi & 0xFFFF0000) == 0x00000000)
                out << " SI=" << std::uppercase << std::setfill('0') << std::setw(4) << std::hex << init->dump.regs.si << " ";               
            else
                out << "ESI=" << std::uppercase << std::setfill('0') << std::setw(8) << std::hex << init->dump.regs.esi << " ";               
        err = uc_reg_write(uc, UC_X86_REG_EBP, &init->dump.regs.ebp);
        if (err != UC_ERR_OK)
           throw Error("VM IA86 - configuration initiale EBP..............[ERREUR]");
        else
        if (init->dump.regs.ebp != 0x00000000) 
            if ((init->dump.regs.ebp & 0xFFFF0000) == 0x00000000)
                out << " BP=" << std::uppercase << std::setfill('0') << std::setw(4) << std::hex << init->dump.regs.bp << " ";               
            else
                out << "EBP=" << std::uppercase << std::setfill('0') << std::setw(8) << std::hex << init->dump.regs.ebp << " ";               
        err = uc_reg_write(uc, UC_X86_REG_ESP, &init->dump.regs.esp);
        if (err != UC_ERR_OK)
           throw Error("VM IA86 - configuration initiale ESP..............[ERREUR]");
        else
        if (init->dump.regs.esp != 0x00000000)
            if ((init->dump.regs.esp & 0xFFFF0000) == 0x00000000)
                out << " SP=" << std::uppercase << std::setfill('0') << std::setw(4) << std::hex << init->dump.regs.sp << " ";               
            else
                out << "ESP=" << std::uppercase << std::setfill('0') << std::setw(8) << std::hex << init->dump.regs.esp << " ";               
        err = uc_reg_write(uc, UC_X86_REG_EBX, &init->dump.regs.ebx);
        if (err != UC_ERR_OK)
           throw Error("VM IA86 - configuration initiale EBX..............[ERREUR]");
        else
        if (init->dump.regs.ebx != 0x00000000)
            if ((init->dump.regs.ebx & 0xFFFF0000) == 0x00000000)
                out << " BX=" << std::uppercase << std::setfill('0') << std::setw(4) << std::hex << init->dump.regs.bx << " ";               
            else
                out << "EBX=" << std::uppercase << std::setfill('0') << std::setw(8) << std::hex << init->dump.regs.ebx << " ";               
        err = uc_reg_write(uc, UC_X86_REG_EDX, &init->dump.regs.edx);
        if (err != UC_ERR_OK)
           throw Error("VM IA86 - configuration initiale EDX..............[ERREUR]");
        else
        if (init->dump.regs.edx != 0x00000000)
            if ((init->dump.regs.edx & 0xFFFF0000) == 0x00000000)
                out << " DX=" << std::uppercase << std::setfill('0') << std::setw(4) << std::hex << init->dump.regs.dx << " ";               
            else
                out << "EDX=" << std::uppercase << std::setfill('0') << std::setw(8) << std::hex << init->dump.regs.edx << " ";               
        err = uc_reg_write(uc, UC_X86_REG_ECX, &init->dump.regs.ecx);
        if (err != UC_ERR_OK)
           throw Error("VM IA86 - configuration initiale ECX..............[ERREUR]");
        else
        if (init->dump.regs.ecx != 0x00000000)
            if ((init->dump.regs.ecx & 0xFFFF0000) == 0x00000000)
                out << " CX=" << std::uppercase << std::setfill('0') << std::setw(4) << std::hex << init->dump.regs.cx << " ";               
            else
                out << "ECX=" << std::uppercase << std::setfill('0') << std::setw(8) << std::hex << init->dump.regs.ecx << " ";               
        err = uc_reg_write(uc, UC_X86_REG_EAX, &init->dump.regs.eax);
        if (err != UC_ERR_OK)
           throw Error("VM IA86 - configuration initiale EAX..............[ERREUR]");
        else
        if (init->dump.regs.eax != 0x00000000)
            if ((init->dump.regs.eax & 0xFFFF0000) == 0x00000000)
                out << " AX=" << std::uppercase << std::setfill('0') << std::setw(4) << std::hex << init->dump.regs.ax << " ";               
            else
                out << "EAX=" << std::uppercase << std::setfill('0') << std::setw(8) << std::hex << init->dump.regs.eax << " ";               
        log->append(out.str());
}

void VMEngine::Run(uint32_t end,uint64_t timeout)
{
    try
    {
        if (verify()==0 && this->initialized)
        {
            err=uc_emu_start(uc, this->getCurrent(), end, timeout, 0);
            if (err) 
            {
                this->Halt();
                throw Error("VM IA86 - execution...............................[ERREUR]");
            }
            else
            {
                if (!this->executed)
                log->append("VM IA86 - execution...............................[ INFO ]");
                this->executed="true";
            }
        }
   }
   catch(exception const& e)
   {
        log->append(e.what());
   }
}

//----------------------------------------------------------------------
// Classe 
//----------------------------------------------------------------------

//----------------------------------------------------------------------
// Classe Menu
//----------------------------------------------------------------------

Menu::Menu (finalcut::FWidget* parent)
  : finalcut::FDialog{parent}
{
  initNow();
}

void Menu::initNow()
{
  initWindows();
  initMisc();
  initMenus();
  initMenusCallBack();
  initCore();
}

void Menu::initCore()
{
  addTimer (50);
  if (scenar.load("./scenarios.json"))
  {
    log.append("Application - charge scénarios....................[  OK  ]");
    log.append("-={ "+ scenario.title+" }=-");
    if (scenario.levels.size()>0)
        loadLevel();
    maxi();
  }
  else
  {
    vm.Unconfigure();
    log.append("Application - charge scénarios....................[ERREUR]");
    mini();
  }
}

void Menu::mini()
{
  this->hide();
  flags.hide();
  stack.hide();
  mem.hide();
  screen.hide();
  log.show();
  edit.hide();
  view.hide();
  regs.hide();
  tuto.hide();
  debug.hide();
  scenar.hide();
  Options.hide();
  Tools.hide();
  Window.hide();
  Debug.hide();
}

void Menu::maxi()
{
    Options.show();
    Tools.show();
    Window.show();
    Debug.show();
}

void Menu::initWindows()
{
  log.setText ("Journaux");
  log.setResizeable();
  log.show();
  edit.setText ("Code source");
  edit.setResizeable();
  edit.show();
  view.setText ("Objectif");
  view.setResizeable();
  view.show();
  regs.setText ("Registres");
  regs.show();
  flags.setText ("Drapeaux");
  stack.setText ("Pile");
  mem.setText ("Mémoire");
  tuto.setText ("Guide");
  tuto.setResizeable();
  tuto.show();
  screen.setText ("Ecran");
  debug.setText ("Instructions");
  debug.setResizeable();
  debug.show();
  scenar.setText ("Scénarios");
  scenar.setResizeable();
  scenar.show();
}

// Level  1 : IP AL
// Level  2 : IP AX
// Level  3 : IP AX BX CX DX
// Level  4 : IP AX BX CX DX FLAGS
// Level  5 : IP AX BX CX DX FLAGS SI DI
// Level  6 : IP AX BX CX DX FLAGS SI DI SP BP
// Level  7 : IP AX BX CX DX FLAGS SI DI SP BP CS DS ES SS
// Level  8 : IP AX BX CX DX FLAGS SI DI SP BP CS DS ES SS FS GS
// Level  9 : EIP EAX EBX ECX EDX EFLAGS ESI EDI ESP EBP CS DS ES SS FS GS
// Level 10 : EIP EAX EBX ECX EDX EFLAGS ESI EDI ESP EBP CS DS ES SS FS GS ST0 ST1 ST2 ST3 ST4 ST5 ST6 ST7
// Level 11 : EIP EAX EBX ECX EDX EFLAGS ESI EDI ESP EBP CS DS ES SS FS GS ST0 ST1 ST2 ST3 ST4 ST5 ST6 ST7 CR0 CR2 CR3 CR4 CR8 
// Level 12 : EIP EAX EBX ECX EDX EFLAGS ESI EDI ESP EBP CS DS ES SS FS GS ST0 ST1 ST2 ST3 ST4 ST5 ST6 ST7 CR0 CR2 CR3 CR4 CR8 DB0 DB1 DB2 DB3 DB6 DB7

void Menu::AdjustWindows()
{
  log.setGeometry ( FPoint { 63, 45 }, FSize{60, 11} );
  edit.setGeometry ( FPoint { 01, 17 }, FSize{39, 27} );
  view.setGeometry ( FPoint { 01, 45 }, FSize{60, 11} );
  regs.setGeometry ( FPoint { 01, 01 }, FSize{40, 15} );
  flags.setGeometry ( FPoint { 60, 01 }, FSize{15, 15} );
  stack.setGeometry ( FPoint { 43, 01 }, FSize{15, 15} );
  mem.setGeometry ( FPoint { 77, 01 }, FSize{108, 15} );
  tuto.setGeometry ( FPoint { 125, 45 }, FSize{60, 11} );
  screen.setGeometry ( FPoint { 105, 18 }, FSize{80, 25} );
  debug.setGeometry ( FPoint { 42, 17 }, FSize{60, 27} );
  scenar.setGeometry ( FPoint { 187, 01 }, FSize{25, 55} );
  this->hide();
  flags.hide();
  stack.hide();
  mem.hide();
  screen.hide();
  log.show();
  edit.show();
  view.show();
  regs.show();
  tuto.show();
  debug.show();
  scenar.show();
  if (scenario.levels[scenar.getselected()].rights > 3)
        flags.show();
  if (scenario.levels[scenar.getselected()].rights > 5)
        stack.show();
  if (scenario.levels[scenar.getselected()].rights > 2)
        mem.show();
  if (scenario.levels[scenar.getselected()].rights > 6)
        screen.show();              
}

void Menu::initMenus()
{
  Game.setStatusbarMessage ("Menu principal du jeu");
  Options.setStatusbarMessage ("Options du logiciel IA86");
  Tools.setStatusbarMessage ("Outils divers");
  Debug.setStatusbarMessage ("Fonctionnalitées de déboguages");
  Window.setStatusbarMessage ("Fenêtres en cours d'exécution");
  Help.setStatusbarMessage ("Aide et informations IA86");
  Line2.setSeparator();
  New.addAccelerator (FKey::Meta_n);
  New.setStatusbarMessage ("Debuter une nouvelle partie"); 
  Quit.addAccelerator (FKey::Meta_x);
  Quit.setStatusbarMessage ("Quitter IA86"); 
  Run.addAccelerator (FKey::F9);
  Run.setStatusbarMessage ("Exécuter le programme - seul un breakpoint arrête"); 
  TraceInto.addAccelerator (FKey::F7);
  TraceInto.setStatusbarMessage ("Pas à pas détaillé - entre dans les CALL"); 
  StepOver.addAccelerator (FKey::F8);
  StepOver.setStatusbarMessage ("Pas à pas - ne rentre pas dans les CALL"); 
  Assemble.addAccelerator (FKey::F2);
  Assemble.setStatusbarMessage ("Assemble le source vers du code machine"); 
  Rearange.addAccelerator (FKey::Meta_r);
  Rearange.setStatusbarMessage ("Reorganise les fenêtres dans leur état initial");   
  Breakpoint.addAccelerator (FKey::F5);
  Breakpoint.setStatusbarMessage ("Enlève ou met un point d'arrêt"); 
  End.addAccelerator (FKey::F6);
  End.setStatusbarMessage ("Termine le programme et remet à zéro la machine IA86");
  About.setStatusbarMessage ("A propos de IA86"); 
}

void Menu::onTimer (finalcut::FTimerEvent* ev)
{
  refresh();
}

void Menu::initMenusCallBack()
{
  Quit.addCallback
  (
    "clicked",
    finalcut::getFApplication(),
    &finalcut::FApplication::cb_exitApp,
    this
  );
  Assemble.addCallback
  (
    "clicked",
    this,
    &Menu::compile
  );
  Run.addCallback
  (
    "clicked",
    this,
    &Menu::exec
  );
  Rearange.addCallback
  (
    "clicked",
    this,
    &Menu::AdjustWindows
  );
  TraceInto.addCallback
  (
    "clicked",
    this,
    &Menu::trace
  );
  StepOver.addCallback
  (
    "clicked",
    this,
    &Menu::step
  );
  End.addCallback
  (
    "clicked",
    this,
    &Menu::end
  );
  About.addCallback
  (
    "clicked",
    this,
    &Menu::about
  );
}

void Menu::initMisc()
{
  Info << " █████   █████████    ████████    ████████ \n"
       << "░░███   ███░░░░░███  ███░░░░███  ███░░░░███\n"
       << " ░███  ░███    ░███ ░███   ░███ ░███   ░░░ \n"
       << " ░███  ░███████████ ░░████████  ░█████████ \n"
       << " ░███  ░███░░░░░███  ███░░░░███ ░███░░░░███\n"
       << " ░███  ░███    ░███ ░███   ░███ ░███   ░███\n"
       << " █████ █████   █████░░████████  ░░████████ \n"
       << "░░░░░ ░░░░░   ░░░░░  ░░░░░░░░    ░░░░░░░░  \n"
       << "THE EVEN MORE PEDAGOGICAL SYSTEM !!\n"
       << "\n"
       << "Episode 1 : Apprendre l'assembleur X86";
    Statusbar.setMessage("THE EVEN MORE PEDAGOGICAL SYSTEM !!");
}

void Menu::initLayout()
{
  Info.setGeometry(FPoint{2, 1}, FSize{43, 12});
  FDialog::initLayout();
}

void Menu::adjustSize()
{
  const auto pw = int(getDesktopWidth());
  const auto ph = int(getDesktopHeight());
  setX (1 + (pw - int(getWidth())) / 2, false);
  setY (1 + (ph - int(getHeight())) / 4, false);
  finalcut::FDialog::adjustSize();
}

void Menu::onClose (finalcut::FCloseEvent* ev)
{
  finalcut::FApplication::closeConfirmationDialog (this, ev);
}

void Menu::loadLevel()
{
  vm.Unconfigure();
  log.append("Application - charge niveau.......................[ INFO ]");
  view.setText("Objectif: "+scenario.levels[scenar.getselected()].title);
  view.clear();
  view.append(scenario.levels[scenar.getselected()].description);
  tuto.clear();
  tuto.append(scenario.levels[scenar.getselected()].tutorial);
  edit.set(scenario.levels[scenar.getselected()].code);
  debug.clear();
  vm.setRights(scenario.levels[scenar.getselected()].rights);
  AdjustWindows();
}

void Menu::end()
{
  vm.Halt();
}

void Menu::compile()
{
    vm.Configure(&scenario.levels[scenar.getselected()].init,edit.get());
    showInstr();
}

void Menu::about()
{
  log.hide();
  edit.hide();
  view.hide();
  regs.hide();
  flags.hide();
  stack.hide();
  mem.hide();
  tuto.hide();
  screen.hide();
  debug.hide();
  scenar.hide();
  this->show();
  this->redraw();
  this->Info.redraw();
  //((finalcut::FApplication*)this->getParent())->sendQueuedEvents();
  sleep(3);
  AdjustWindows();
}

void Menu::showInstr()
{
    try
    {
        if (vm.isInitialized())
        {
            debug.set(vm.getInstr(vm.getCS(),vm.getEIP(),debug.getHeight()-3));
            debug.setmark(vm.getLine());
        }
    }
    catch(exception const& e)
    {
        log.append(e.what());
        vm.Halt();
    }
}

void Menu::refresh()
{
  if (!vm.isInitialized())
  {
    regs.set("En attente d'initialisation...");
    flags.set("Attente...");   
  }
  else
  {
      try
    {
        regs.set(vm.getRegs());
        flags.set(vm.getFlags());
    }
    catch(exception const& e)
    {
        log.append(e.what());
        vm.Halt();
    }
  }
  if (!vm.isExecuted())
  {
    finalcut::FApplication::setDarkTheme();
  }
  else
  {
    finalcut::FApplication::setDefaultTheme();
  }
  auto root_widget = getRootWidget();
  root_widget->resetColors();
  root_widget->redraw();

}

void Menu::exec()
{
  if (!vm.isInitialized())
    compile();
   vm.Run(0xFFFF,0);
   showInstr();
}

void Menu::trace()
{
  if (!vm.isInitialized())
    compile();
  vm.Run(vm.getNextInstr(),0);
  showInstr();
}

void Menu::step()
{
  if (!vm.isInitialized())
    compile(); 
  vm.Run(vm.getNextInstr(),0);
  showInstr();
}

//----------------------------------------------------------------------
// Fonction Main
//----------------------------------------------------------------------
int main (int argc, char* argv[])
{
  mapping();
  finalcut::FApplication app {argc, argv};
  Menu main_dlg {&app};
  main_dlg.setText ("IA86");
  main_dlg.setSize ({50, 14});
  main_dlg.setShadow();
  main_dlg.show();
  finalcut::FApplication::setDarkTheme();
  finalcut::FWidget::setMainWidget (&main_dlg);
  //usleep(5 * 1000000);
  main_dlg.hide();
  return app.exec();
}
