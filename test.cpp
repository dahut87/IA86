#include <final/final.h>
#include <iostream>
#include <string>
#include <sstream>
#include <keystone/keystone.h>
#include <unicorn/unicorn.h>
#include <capstone/capstone.h>
using namespace std;

using FKey = finalcut::FKey;
using finalcut::FPoint;
using finalcut::FSize;
   
   

//----------------------------------------------------------------------
// class TextFixedWindow
//----------------------------------------------------------------------

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
    void refresh ();
  private:
    // Method
    void initLayout() override;
    void adjustSize() override;
    // Data members
    finalcut::FLabel fixedtext{this};
};

//----------------------------------------------------------------------
TextFixedWindow::TextFixedWindow (finalcut::FWidget* parent)
  : finalcut::FDialog{parent}
{

  fixedtext.setText("pour voir"); 
  fixedtext.ignorePadding();
  fixedtext.setFocus();
}

//----------------------------------------------------------------------
void TextFixedWindow::refresh ()
{
  
}

//----------------------------------------------------------------------
void TextFixedWindow::initLayout()
{
  fixedtext.setGeometry (FPoint{1, 2}, FSize{getWidth(), getHeight() - 1});
  setMinimumSize (FSize{51, 6});
  FDialog::initLayout();
}

//----------------------------------------------------------------------
void TextFixedWindow::adjustSize()
{
  finalcut::FDialog::adjustSize();
  fixedtext.setGeometry (FPoint{1, 2}, FSize(getWidth(), getHeight() - 1));
}


//----------------------------------------------------------------------
// class TextWindow
//----------------------------------------------------------------------

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
    void append (const finalcut::FString&);
  private:
    // Method
    void initLayout() override;
    void adjustSize() override;
    // Data members
    finalcut::FTextView scrolltext{this};
};

//----------------------------------------------------------------------
TextWindow::TextWindow (finalcut::FWidget* parent)
  : finalcut::FDialog{parent}
{
  scrolltext.ignorePadding();
  scrolltext.setFocus();
}

//----------------------------------------------------------------------
void TextWindow::append (const finalcut::FString& str)
{
  scrolltext.append(str);
}

//----------------------------------------------------------------------
void TextWindow::initLayout()
{
  scrolltext.setGeometry (FPoint{1, 2}, FSize{getWidth(), getHeight() - 1});
  setMinimumSize (FSize{51, 6});
  FDialog::initLayout();
}

//----------------------------------------------------------------------
void TextWindow::adjustSize()
{
  finalcut::FDialog::adjustSize();
  scrolltext.setGeometry (FPoint{1, 2}, FSize(getWidth(), getHeight() - 1));
}

//----------------------------------------------------------------------
// class Menu
//----------------------------------------------------------------------

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
    // Structures
    struct Goal {
        string title;
        string description;
    };
     // Methods
    void loadGoal(Goal *g);
  private:
    // Methods
    void configureFileMenuItems();
    void defaultCallback (const finalcut::FMenuList*);
    void initLayout() override;
    void adjustSize() override;
    // Event handler
    void onClose (finalcut::FCloseEvent*) override;
    // Callback method
    void cb_message (const finalcut::FMenuItem*);
    // Data members
    finalcut::FString        line{13, finalcut::UniChar::BoxDrawingsHorizontal};
    finalcut::FMenuBar       Menubar{this};
    finalcut::FMenu          File{"&Menu", &Menubar};
    finalcut::FMenuItem      Line2{&File};
    finalcut::FMenuItem      Quit{"&Quit", &File};
    finalcut::FMenuItem      Window{"&Windows", &Menubar};
    finalcut::FLabel         Info{this};
    finalcut::FStatusBar     Statusbar{this};

};

//----------------------------------------------------------------------
Menu::Menu (finalcut::FWidget* parent)
  : finalcut::FDialog{parent}
{
  File.setStatusbarMessage ("main menu");
  Window.setDisable();
  configureFileMenuItems();
  defaultCallback (&Menubar);
  Statusbar.setMessage("Status bar message");
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
}

//----------------------------------------------------------------------
void Menu::configureFileMenuItems()
{
  Line2.setSeparator();
  Quit.addAccelerator (FKey::Meta_x);
  Quit.setStatusbarMessage ("Quit the program");
  Quit.addCallback
  (
    "clicked",
    finalcut::getFApplication(),
    &finalcut::FApplication::cb_exitApp,
    this
  );
}

//----------------------------------------------------------------------
void Menu::defaultCallback (const finalcut::FMenuList* mb)
{
  for (uInt i{1}; i <= mb->getCount(); i++)
  {
    auto item = mb->getItem(int(i));

    if ( item
      && item->isEnabled()
      && item->acceptFocus()
      && item->isVisible()
      && ! item->isSeparator()
      && item->getText() != "&Quit" )
    {
      item->addCallback
      (
        "clicked",
        this, &Menu::cb_message,
        item
      );
      if ( item->hasMenu() )
        defaultCallback (item->getMenu());
    }
  }
}

//----------------------------------------------------------------------
void Menu::initLayout()
{
  Info.setGeometry(FPoint{2, 1}, FSize{43, 12});
  FDialog::initLayout();
}

//----------------------------------------------------------------------
void Menu::adjustSize()
{
  const auto pw = int(getDesktopWidth());
  const auto ph = int(getDesktopHeight());
  setX (1);
  setY (1);
  finalcut::FDialog::adjustSize();
}

//----------------------------------------------------------------------
void Menu::onClose (finalcut::FCloseEvent* ev)
{
  finalcut::FApplication::closeConfirmationDialog (this, ev);
}

//----------------------------------------------------------------------
void Menu::cb_message (const finalcut::FMenuItem* menuitem)
{
  auto text = menuitem->getText();
  text = text.replace('&', "");
  finalcut::FMessageBox::info ( this
                              , "Info"
                              , "You have chosen \"" + text + "\"" );
}

void Menu::loadGoal(Goal *g)
{
  const auto& view = new TextWindow(this);
  view->setText ("Objectif: "+g->title);
  view->setGeometry ( FPoint { 10, 10 }, FSize{60, 12} );
  view->setResizeable();
  view->append(g->description);
  view->show();
  const auto& test = new TextFixedWindow(this);
  test->setText ("test");
  test->setGeometry ( FPoint { 20, 10 }, FSize{30, 12} );
  test->show();  
}

//----------------------------------------------------------------------
// class VMEngine
//----------------------------------------------------------------------

class VMEngine
{
  public:
    VMEngine(TextWindow *T);
  private:
    uc_engine *uc;
    uc_err err;
    TextWindow *T;
    std::ostringstream out;
};

VMEngine::VMEngine(TextWindow *T) : T(T)
{
    err = uc_open(UC_ARCH_X86, UC_MODE_16, &uc);
    if (err != UC_ERR_OK) {
        out << "Failed on uc_open() with error returned: " << err;
        T->append(out.str());
    }
    out << "Failed on uc_open() with error returned: " << "ok";
        T->append(out.str());

}

/*VMEngine::Configure(int address)
{

}

VMEngine::Run()
{

}

   /*uc_mem_map(uc, ADDRESS, 1 * 1024 * 1024, UC_PROT_ALL);
   if (uc_mem_write(uc, ADDRESS, encode, sizecode)) {
     printf("Failed to write emulation code to memory, quit!\n");
     return -1;
   }
   uc_reg_write(uc, UC_X86_REG_CX, &r_cx);
   uc_reg_write(uc, UC_X86_REG_DX, &r_dx);
   uc_reg_read(uc, UC_X86_REG_IP, &r_ip);
   error=uc_emu_start(uc, ADDRESS, ADDRESS + sizecode, 0, 0);
   if (error) {
     printf("Failed on uc_emu_start() with error returned %u: %s\n",
       err, uc_strerror(error));
   }
   printf("Emulation done. Below is the CPU context\n"); 
   uc_reg_read(uc, UC_X86_REG_CX, &r_cx);
   uc_reg_read(uc, UC_X86_REG_DX, &r_dx);
   uc_reg_read(uc, UC_X86_REG_IP, &r_ip);
   printf(">>> CX = 0x%x\n", r_cx);
   printf(">>> DX = 0x%x\n", r_dx);
   printf(">>> IP = 0x%x\n", r_ip);*/







//----------------------------------------------------------------------
//                               main part
//----------------------------------------------------------------------

int main (int argc, char* argv[])
{
  Menu::Goal goals[]={ {"Numération","Le première objectif vise à savoir convertir des nombres d'une base de numération à une autre."},{"L'instruction MOV",""},{"La mémoire",""}, };
  finalcut::FApplication app {argc, argv};
  Menu main_dlg {&app};
  main_dlg.setText ("IA86 -  Main window");
  main_dlg.setSize ({50, 14});
  main_dlg.setShadow();
  TextWindow log {&main_dlg};
  log.setText ("Journaux");
  log.setGeometry ( FPoint { 30, 10 }, FSize{60, 12} );
  log.setResizeable();
  log.append("lancement des journaux");
  log.show();
  finalcut::FWidget::setMainWidget (&main_dlg);
  main_dlg.show();
  main_dlg.loadGoal(&goals[0]);
  VMEngine vm {&log};
  return app.exec();
}
