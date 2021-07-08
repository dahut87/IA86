#include <final/final.h>
#include <unistd.h>
#include <iostream>
#include <sstream>
#include <string>
#include <sstream>
#include <iomanip>
#include <keystone/keystone.h>
#include <unicorn/unicorn.h>
#include <capstone/capstone.h>
#include <vector>
#include "ia86.h"

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
    struct_mapping::reg(&Scenario::Levels, "scenario_objectifs");
    struct_mapping::reg(&Level::title, "niveau_titre");
    struct_mapping::reg(&Level::description, "niveau_description");
    struct_mapping::reg(&Level::tutorial, "niveau_tutoriel");
    struct_mapping::reg(&Level::code, "niveau_code");
    struct_mapping::reg(&Level::level, "niveau_droits");
    struct_mapping::reg(&Level::init, "niveau_initial");
    struct_mapping::reg(&Level::goal, "niveau_objectif");
    struct_mapping::reg(&State::dump, "registres");
    struct_mapping::reg(&State::memzone, "memoires");
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

//----------------------------------------------------------------------
// Classe ScenarioWindow
//----------------------------------------------------------------------

ScenarioWindow::ScenarioWindow (finalcut::FWidget* parent)
  : finalcut::FDialog{parent}
{
  scenario=readscenario("./scenarios.txt");
  listview.ignorePadding();
  listview.addColumn ("*");
  listview.addColumn ("Intitulé");  
  listview.hideSortIndicator(true);
  listview.setFocus();
  std::vector<std::string> items;
  for(size_t i=0; i < (sizeof(scenario.Levels)/sizeof(scenario.Levels[0])); i++)
  {
    items.clear();
    items.push_back(to_string(i));
    items.push_back(scenario.Levels[i].title);
    const finalcut::FStringList line (items.begin(), items.end());    
    listview.insert (line);
  }
  listview.addCallback
  (
    "row-changed",
    this, &ScenarioWindow::click
  );
}

void ScenarioWindow::click()
{
    const auto& item = listview.getCurrentItem();
    std::string temp=item->getText(1).toString();
    selected=stoi(temp);
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

void InstructionWindow::setindex(int index)
{
  listview.setindex(index);
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
    std::stringstream out;
    err = cs_open(CS_ARCH_X86, CS_MODE_16, &handle);
    if (err != CS_ERR_OK) {
        out << "Erreur : Initialisation du désassembleur X86" << err;
        log->append(out.str());
    }
    else
        log->append("Initialisation du désassembleur X86");
}

std::vector<std::array<std::string, 5>> Desassembler::Desassemble(Code *code)
{
    std::stringstream out;
    srcsize=cs_disasm(handle, code->content, code->size, code->address, 0, &insn);
    if (srcsize == 0)
        log->append("Erreur de désassemblage");
    else
    {  
        out << "Désassemblage réussi, taille du source :" << srcsize;
        log->append(out.str());
        src.clear();
		for (size_t j = 0; j < srcsize; j++)
		{
		    std::string *bytes = new std::string("");
		    for (size_t k = 0; k < insn[j].size; k++)
                *bytes=*bytes+intToHexString((int)insn[j].bytes[k], 2);
            std::string adresse = intToHexString((int)insn[j].address, 8);  
		    std::string *menmonic = new std::string((char *)insn[j].mnemonic);
		    std::string *op_str = new std::string((char *)insn[j].op_str);
		    std::array<std::string, 5> *array = new  std::array<std::string, 5>{"", adresse, *bytes, *menmonic, *op_str};
		    src.push_back(*array);
        }
		cs_free(insn, srcsize);
    }
    return src;
}

//----------------------------------------------------------------------
// Classe Assembler
//----------------------------------------------------------------------

Assembler::Assembler(TextWindow *log) : log(log)
{
    std::stringstream out;
    err = ks_open(KS_ARCH_X86, KS_MODE_16, &ks);
    if (err != KS_ERR_OK) {
        out << "Erreur : Initialisation de l'assembleur X86" << err;
        log->append(out.str());
    }
    else
        log->append("Initialisation de l'assembleur X86");
    code->assembled=false;
}

Code *Assembler::Assemble(std::string source,uint32_t address)
{
    std::stringstream out;
    code->address=address;
    size_t srcsize=source.size();
    unsigned char src_char[srcsize+1];
    strcpy(reinterpret_cast<char*>(src_char), source.c_str());
    err2=ks_asm(ks, reinterpret_cast<const char*>(src_char), code->address, &code->content, &code->size, &srcsize);
    if (err2 != KS_ERR_OK)
    {
        log->append("Erreur d'assemblage");
        code->size=0;
        code->assembled=false;
    }
    else
    {  
        out << "Assemblage réussi, taille du code :" << code->size;
        code->assembled=true;
        log->append(out.str());
        /*out.str("");
        out.clear();
        if (codesize < 30)
        {
               out << "  ";
               for (size_t count = 0; count < codesize; count++)
                    out << std::uppercase << std::setfill('0') << std::setw(2) << std::hex << (int)((uint8_t)code[count]) ;
               log->append(out.str());   
        }*/
    }
    return code;
}
 
//----------------------------------------------------------------------
// Classe VMEngine
//----------------------------------------------------------------------

VMEngine::VMEngine(TextWindow *log) : log(log)
{
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
std::string VMEngine::getFlags(int level)
{
        int eflags=0;
        err = uc_reg_read(uc, UC_X86_REG_EFLAGS, &eflags);
        if (err != UC_ERR_OK)
           log->append("Impossible de récupérer le registre: EFLAGS");
        std::stringstream out;
        out << "  CF:" << std::dec << ((eflags & 0x0001));
        if (level > 8) 
            out << "  RF:" << std::dec << ((eflags & 0x00010000)>>16) << "\n";
        else
            out << "\n"; 
        out << "  PF:" << std::dec << ((eflags & 0x0004)>>2); 
        if (level > 8)
            out << "  VM:" << std::dec << ((eflags & 0x00020000)>>17) << "\n";
        else
            out << "\n";
        out << "  AF:" << std::dec << ((eflags & 0x0010)>>4);    
        if (level > 8)
            out << "  AC:" << std::dec << ((eflags & 0x00040000)>>18) << "\n";
        else
            out << "\n";
        out << "  ZF:" << std::dec << ((eflags & 0x0040)>>6);
        if (level > 8)
            out << " VIF:" << std::dec << ((eflags & 0x00080000)>>19) << "\n";
        else
            out << "\n";
        out << "  SF:" << std::dec << ((eflags & 0x0080)>>7);
        if (level > 8)
            out << " VIP:" << std::dec << ((eflags & 0x00100000)>>20) << "\n";      
        else
            out << "\n";
        out << "  TF:" << std::dec << ((eflags & 0x0100)>>8);
        if (level > 8)
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

std::string VMEngine::getRegs(int level)
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
        log->append("Erreur lors de la récupération des registres depuis la VM");
        return "";
    }
    std::stringstream out;
    if (level > 8)
        out << "EAX:" << std::uppercase << std::setfill('0') << std::setw(8) << std::hex << vals[0] << " | ";
    if (level > 1)
        out << "AX:" << std::uppercase << std::setfill('0') << std::setw(4) << std::hex << (vals[0] & 0x0000FFFF) << " | "; 
    if (level > 1)
        out << "AH:" << std::uppercase << std::setfill('0') << std::setw(2) << std::hex << ((vals[0] & 0xFF00) >> 8) << " | "; 
    out << "AL:" << std::uppercase << std::setfill('0') << std::setw(2) << std::hex << (vals[0] & 0xFF) << "\n"; 

    if (level > 8)
        out << "EBX:" << std::uppercase << std::setfill('0') << std::setw(8) << std::hex << vals[1] << " | ";
    if (level > 2)
        out << "BX:" << std::uppercase << std::setfill('0') << std::setw(4) << std::hex << (vals[1] & 0x0000FFFF) << " | "; 
    if (level > 2)
        out << "BH:" << std::uppercase << std::setfill('0') << std::setw(2) << std::hex << ((vals[1] & 0xFF00) >> 8) << " | "; 
    if (level > 2)
        out << "BL:" << std::uppercase << std::setfill('0') << std::setw(2) << std::hex << (vals[1] & 0xFF) << "\n"; 
    
    if (level > 8)
        out << "ECX:" << std::uppercase << std::setfill('0') << std::setw(8) << std::hex << vals[2] << " | ";
    if (level > 2)
        out << "CX:" << std::uppercase << std::setfill('0') << std::setw(4) << std::hex << (vals[2] & 0x0000FFFF) << " | "; 
    if (level > 2)
        out << "CH:" << std::uppercase << std::setfill('0') << std::setw(2) << std::hex << ((vals[2] & 0xFF00) >> 8) << " | "; 
    if (level > 2)
        out << "CL:" << std::uppercase << std::setfill('0') << std::setw(2) << std::hex << (vals[2] & 0xFF) << "\n"; 
    
    if (level > 8)
        out << "EDX:" << std::uppercase << std::setfill('0') << std::setw(8) << std::hex << vals[3] << " | ";
    if (level > 2)
        out << "DX:" << std::uppercase << std::setfill('0') << std::setw(4) << std::hex << (vals[3] & 0x0000FFFF) << " | "; 
    if (level > 2)
        out << "DH:" << std::uppercase << std::setfill('0') << std::setw(2) << std::hex << ((vals[3] & 0xFF00) >> 8) << " | "; 
    if (level > 2)
        out << "DL:" << std::uppercase << std::setfill('0') << std::setw(2) << std::hex << (vals[3] & 0xFF) << "\n"; 
    
    if (level > 8)
        out << "ESI:" << std::uppercase << std::setfill('0') << std::setw(8) << std::hex << vals[4] << " | ";
    if (level > 4)    
        out << "SI:" << std::uppercase << std::setfill('0') << std::setw(4) << std::hex << (vals[4] & 0x0000FFFF) << "\n"; 
    if (level > 8)
        out << "EDI:" << std::uppercase << std::setfill('0') << std::setw(8) << std::hex << vals[5] << " | ";
    if (level > 4)
        out << "DI:" << std::uppercase << std::setfill('0') << std::setw(4) << std::hex << (vals[5] & 0x0000FFFF) << "\n";
    
    if (level > 8)
        out << "EBP:" << std::uppercase << std::setfill('0') << std::setw(8) << std::hex << vals[6] << " | ";
    if (level > 5)
        out << "BP:" << std::uppercase << std::setfill('0') << std::setw(4) << std::hex << (vals[6] & 0x0000FFFF) << "\n"; 
    if (level > 8)
        out << "ESP:" << std::uppercase << std::setfill('0') << std::setw(8) << std::hex << vals[7] << " | ";
    if (level > 5)
        out << "SP:" << std::uppercase << std::setfill('0') << std::setw(4) << std::hex << (vals[7] & 0x0000FFFF) << "\n";
    
    if (level > 6)
        out << "CS:" << std::uppercase << std::setfill('0') << std::setw(4) << std::hex << (vals[8] & 0x0000FFFF) << " | "; 
    if (level > 6)
        out << "DS:" << std::uppercase << std::setfill('0') << std::setw(4) << std::hex << (vals[9] & 0x0000FFFF) << " | "; 
    if (level > 6)
        out << "ES:" << std::uppercase << std::setfill('0') << std::setw(4) << std::hex << (vals[10] & 0x0000FFFF) << "\n"; 
    if (level > 6)
        out << "SS:" << std::uppercase << std::setfill('0') << std::setw(4) << std::hex << (vals[11] & 0x0000FFFF) << " | "; 
    if (level > 7)
        out << "FS:" << std::uppercase << std::setfill('0') << std::setw(4) << std::hex << (vals[12] & 0x0000FFFF) << " | ";
    if (level > 7) 
        out << "GS:" << std::uppercase << std::setfill('0') << std::setw(4) << std::hex << (vals[13] & 0x0000FFFF) << "\n"; 
    
    if (level > 8)
        out << "EIP:" << std::uppercase << std::setfill('0') << std::setw(8) << std::hex << vals[14] << " | ";
    out << "IP:" << std::uppercase << std::setfill('0') << std::setw(4) << std::hex << (vals[14] & 0x0000FFFF) << "\n";
    
    if (level > 3)
    if (level < 9)
        out << "FLAGS:" << std::uppercase << std::setfill('0') << std::setw(8) << std::hex << (vals[15]  & 0xFFFF)<< ""; 
    else
        out << "EFLAGS:" << std::uppercase << std::setfill('0') << std::setw(8) << std::hex << vals[15] << ""; 
    return out.str();
}

void VMEngine::Init()
{
    std::stringstream out; 
    err = uc_open(UC_ARCH_X86, UC_MODE_16, &uc);
    if (err != UC_ERR_OK) {
        out << "Impossible d'initialiser la machine virtuelle: " << err;
        log->append(out.str());
    }
    else
        log->append("Initialisation de l'ordinateur IA86");
}

void VMEngine::Close()
{
   uc_close(uc);
}

void VMEngine::Halt(Code *code)
{
   code->executed=false;
}

void VMEngine::Configure(State *init, Code *code)
{
    Close();
    Init();
    code->assembled=false;
    code->initialized=false;
    code->executed=false;
    log->append("Mappage de la mémoire virtuelle");
    uc_mem_map(uc, init->dump.regs.eip, 1 * 1024 * 1024, UC_PROT_ALL);
}

void VMEngine::Prepare(State *init, Code *code)
{
    SetMem(init, code);
    SetRegs(init, code);
}

int VMEngine::getEIP(Code *code)
{
        int eip=-666;
        err = uc_reg_read(uc, UC_X86_REG_EIP, &eip);
        if (err != UC_ERR_OK)
           log->append("Impossible de récupérer le registre: EIP");
        if ((eip<code->address) || (eip>code->address+code->size))
            eip=-666;
        return eip;
        }

void VMEngine::SetMem(State *init, Code *code)
{

        err = uc_mem_write(uc, init->dump.regs.eip, code->content, code->size);
        if (err) 
        {
            code->initialized=false;
            log->append("Erreur de copie mémoire dans la machine virtuelle");
            return;
        }
        else
        {
            code->initialized=true;
            log->append("Chargement en mémoire de la machine virtuelle, taille: "+to_string(code->size));
        }
}
 
void VMEngine::SetRegs(State *init, Code *code)
{
        std::stringstream out;
        out << "Configuration initiale de l'ordinateur IA86:\n  "; 
        err = uc_reg_write(uc, UC_X86_REG_EIP, &init->dump.regs.eip);
        if (err != UC_ERR_OK)
           log->append("Impossible d'initialiser le registre: EIP");
        else
        if (init->dump.regs.eip != 0x00000000)
            if ((init->dump.regs.eip & 0xFFFF0000) == 0x00000000)
                out << " IP=" << std::uppercase << std::setfill('0') << std::setw(4) << std::hex << init->dump.regs.ip << " ";               
            else
                out << "EIP=" << std::uppercase << std::setfill('0') << std::setw(8) << std::hex << init->dump.regs.eip << " ";     
        err = uc_reg_write(uc, UC_X86_REG_EDI, &init->dump.regs.edi);
        if (err != UC_ERR_OK)
           log->append("Impossible d'initialiser le registre: EDI");
        else
        if (init->dump.regs.edi != 0x00000000)
            if ((init->dump.regs.edi & 0xFFFF0000) == 0x00000000)
                out << " DI=" << std::uppercase << std::setfill('0') << std::setw(4) << std::hex << init->dump.regs.di << " ";               
            else
                out << "EDI=" << std::uppercase << std::setfill('0') << std::setw(8) << std::hex << init->dump.regs.edi << " ";               
        err = uc_reg_write(uc, UC_X86_REG_ESI, &init->dump.regs.esi);
        if (err != UC_ERR_OK)
           log->append("Impossible d'initialiser le registre: ESE");
        else
        if (init->dump.regs.esi != 0x00000000)
            if ((init->dump.regs.esi & 0xFFFF0000) == 0x00000000)
                out << " SI=" << std::uppercase << std::setfill('0') << std::setw(4) << std::hex << init->dump.regs.si << " ";               
            else
                out << "ESI=" << std::uppercase << std::setfill('0') << std::setw(8) << std::hex << init->dump.regs.esi << " ";               
        err = uc_reg_write(uc, UC_X86_REG_EBP, &init->dump.regs.ebp);
        if (err != UC_ERR_OK)
           log->append("Impossible d'initialiser le registre: EBP");
        else
        if (init->dump.regs.ebp != 0x00000000) 
            if ((init->dump.regs.ebp & 0xFFFF0000) == 0x00000000)
                out << " BP=" << std::uppercase << std::setfill('0') << std::setw(4) << std::hex << init->dump.regs.bp << " ";               
            else
                out << "EBP=" << std::uppercase << std::setfill('0') << std::setw(8) << std::hex << init->dump.regs.ebp << " ";               
        err = uc_reg_write(uc, UC_X86_REG_ESP, &init->dump.regs.esp);
        if (err != UC_ERR_OK)
           log->append("Impossible d'initialiser le registre: ESP");
        else
        if (init->dump.regs.esp != 0x00000000)
            if ((init->dump.regs.esp & 0xFFFF0000) == 0x00000000)
                out << " SP=" << std::uppercase << std::setfill('0') << std::setw(4) << std::hex << init->dump.regs.sp << " ";               
            else
                out << "ESP=" << std::uppercase << std::setfill('0') << std::setw(8) << std::hex << init->dump.regs.esp << " ";               
        err = uc_reg_write(uc, UC_X86_REG_EBX, &init->dump.regs.ebx);
        if (err != UC_ERR_OK)
           log->append("Impossible d'initialiser le registre: EBX");
        else
        if (init->dump.regs.ebx != 0x00000000)
            if ((init->dump.regs.ebx & 0xFFFF0000) == 0x00000000)
                out << " BX=" << std::uppercase << std::setfill('0') << std::setw(4) << std::hex << init->dump.regs.bx << " ";               
            else
                out << "EBX=" << std::uppercase << std::setfill('0') << std::setw(8) << std::hex << init->dump.regs.ebx << " ";               
        err = uc_reg_write(uc, UC_X86_REG_EDX, &init->dump.regs.edx);
        if (err != UC_ERR_OK)
           log->append("Impossible d'initialiser le registre: EDX");
        else
        if (init->dump.regs.edx != 0x00000000)
            if ((init->dump.regs.edx & 0xFFFF0000) == 0x00000000)
                out << " DX=" << std::uppercase << std::setfill('0') << std::setw(4) << std::hex << init->dump.regs.dx << " ";               
            else
                out << "EDX=" << std::uppercase << std::setfill('0') << std::setw(8) << std::hex << init->dump.regs.edx << " ";               
        err = uc_reg_write(uc, UC_X86_REG_ECX, &init->dump.regs.ecx);
        if (err != UC_ERR_OK)
           log->append("Impossible d'initialiser le registre: ECX");
        else
        if (init->dump.regs.ecx != 0x00000000)
            if ((init->dump.regs.ecx & 0xFFFF0000) == 0x00000000)
                out << " CX=" << std::uppercase << std::setfill('0') << std::setw(4) << std::hex << init->dump.regs.cx << " ";               
            else
                out << "ECX=" << std::uppercase << std::setfill('0') << std::setw(8) << std::hex << init->dump.regs.ecx << " ";               
        err = uc_reg_write(uc, UC_X86_REG_EAX, &init->dump.regs.eax);
        if (err != UC_ERR_OK)
           log->append("Impossible d'initialiser le registre: EAX");
        else
        if (init->dump.regs.eax != 0x00000000)
            if ((init->dump.regs.eax & 0xFFFF0000) == 0x00000000)
                out << " AX=" << std::uppercase << std::setfill('0') << std::setw(4) << std::hex << init->dump.regs.ax << " ";               
            else
                out << "EAX=" << std::uppercase << std::setfill('0') << std::setw(8) << std::hex << init->dump.regs.eax << " ";               
        log->append(out.str());
}

void VMEngine::Run(Code *code,uint32_t start, uint32_t stop, uint64_t timeout)
{
    err=uc_emu_start(uc, start, stop, timeout, 0);
    if (err) 
    {
        log->append("Erreur lors de l'exécution de la machine virtuelle");
        code->executed=false;
        return;
    }
    else
    {
        code->executed="true";
    }
}

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
    log.append(scenario.title);
  loadLevel();
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
  if (scenario.Levels[scenar.getselected()].level > 3)
        flags.show();
  if (scenario.Levels[scenar.getselected()].level > 5)
        stack.show();
  if (scenario.Levels[scenar.getselected()].level > 2)
        mem.show();
  if (scenario.Levels[scenar.getselected()].level > 6)
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
  Init.addAccelerator (FKey::F3);
  Init.setStatusbarMessage ("Initialise la machine IA86");
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
    &Menu::initWindows
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
  Init.addCallback (
    "clicked",
    this,
    &Menu::verify
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
  log.append("Chargement du scénario "+scenario.Levels[scenar.getselected()].title);
  view.setText("Objectif: "+scenario.Levels[scenar.getselected()].title);
  view.clear();
  view.append(scenario.Levels[scenar.getselected()].description);
  tuto.clear();
  tuto.append(scenario.Levels[scenar.getselected()].tutorial);
  regs.set("En attente d'initialisation...");
  edit.set(scenario.Levels[scenar.getselected()].code);
  AdjustWindows();
  debug.clear();
  vm.Configure(&scenario.Levels[scenar.getselected()].init,code);
  end();
}

void Menu::end()
{
  vm.Halt(code);
}

void Menu::compile()
{
  code=asmer.Assemble(edit.get(),scenario.Levels[scenar.getselected()].init.dump.regs.eip);
  debug.set(unasmer.Desassemble(code));
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

bool Menu::verify()
{
  if (!code->assembled)
  {
    finalcut::FMessageBox::error(this, "Vous devez compiler le source d'abord !");
    return false;
  }
  if (!code->initialized)
    vm.Prepare(&scenario.Levels[scenar.getselected()].init,code);
  if (!code->initialized)
    return false;
  return true;
}

void Menu::refresh()
{
  if (!code->initialized)
  {
    regs.set("En attente d'initialisation...");
    flags.set("Attente...");  
    //debug.setindex(-666);  
  }
  else
  {
    regs.set(vm.getRegs(scenario.Levels[scenar.getselected()].level));
    flags.set(vm.getFlags(scenario.Levels[scenar.getselected()].level));
    //debug.setindex(vm.getEIP(code));  
  }
  if (!code->executed)
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
  if (!verify()) return;
  vm.Run(code,code->address,code->address+code->size,0);
}

void Menu::trace()
{
  if (!verify()) return; 
}

void Menu::step()
{
  if (!verify()) return;  
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
