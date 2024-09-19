using System;
using System.Windows;


namespace Client_Application
{
    /// <summary>
    /// Interaction logic for Startup_window.xaml
    /// </summary>
    public partial class Startup_window  : Window 
    {
        public Startup_window()
        {
            InitializeComponent();
        }

        private void EnterButton_Click(object sender, RoutedEventArgs e)
        {
            MainWindow mainwindow = new MainWindow();
            mainwindow.UsernameValueLabel.Content = enterUsernameBox.Text;
            mainwindow.Show();
            this.Close();
        }
    }
}
