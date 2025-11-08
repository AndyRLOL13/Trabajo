import tkinter as tk
from tkinter import messagebox, ttk
import requests
import os

API_URL = "http://127.0.0.1:8000"

# Globals
token_actual = None
usuario_actual = None
root = None


def guardar_token_local(usuario, token):
    os.makedirs("data", exist_ok=True)
    with open(os.path.join("data", "tokens_local.txt"), "a", encoding="utf-8") as f:
        f.write(f"{usuario} | {token}\n")


def obtener_headers():
    if token_actual:
        return {"Authorization": f"Bearer {token_actual}"}
    return {}


# =======================
# LOGIN / REGISTRO
# =======================
def iniciar_sesion(usuario, contrasena, login_win):
    global token_actual, usuario_actual
    if not usuario or not contrasena:
        messagebox.showwarning("Error", "Debes ingresar usuario y contraseña")
        return

    try:
        resp = requests.post(f"{API_URL}/auth/login", data={"username": usuario, "password": contrasena}, timeout=5)
        if resp.status_code == 200:
            data = resp.json()
            token_actual = data.get("access_token")
            usuario_actual = usuario
            guardar_token_local(usuario, token_actual)
            login_win.destroy()

            me = requests.get(f"{API_URL}/users/me", headers=obtener_headers())
            if me.status_code == 200:
                roles = me.json().get("roles", [])
                roles = [r if isinstance(r, str) else r.get("name") for r in roles]
                if "ADMIN" in roles:
                    abrir_interfaz_admin()
                else:
                    abrir_interfaz_usuario()
            else:
                abrir_interfaz_usuario()
        else:
            messagebox.showerror("Login fallido", resp.json().get("detail", resp.text))
    except Exception as e:
        messagebox.showerror("Error", f"No se pudo conectar al servidor:\n{e}")


def registrar_usuario(usuario, contrasena, login_win):
    global token_actual, usuario_actual
    if not usuario or not contrasena:
        messagebox.showwarning("Error", "Debes ingresar usuario y contraseña")
        return
    try:
        resp = requests.post(f"{API_URL}/auth/register", json={"username": usuario, "password": contrasena}, timeout=5)
        if resp.status_code in (200, 201):
            data = resp.json()
            token = data.get("access_token") or data.get("token")
            if token:
                token_actual = token
                usuario_actual = usuario
                guardar_token_local(usuario, token)
                login_win.destroy()
                abrir_interfaz_usuario()
            else:
                messagebox.showinfo("Registro", "Usuario registrado. Inicia sesión.")
        else:
            messagebox.showerror("Error", resp.json().get("detail", resp.text))
    except Exception as e:
        messagebox.showerror("Error", f"No se pudo conectar al servidor:\n{e}")


# =======================
# INTERFACES
# =======================
def cerrar_sesion(win):
    global token_actual, usuario_actual
    token_actual = None
    usuario_actual = None
    win.destroy()
    mostrar_login()


def abrir_interfaz_usuario():
    user_win = tk.Toplevel(root)
    user_win.title("Panel de Usuario")
    user_win.geometry("300x150")

    tk.Label(user_win, text=f"Usuario: {usuario_actual}", font=("Arial", 12, "bold")).pack(pady=8)
    tk.Label(user_win, text="Usuario ingresado correctamente.").pack(pady=6)
    tk.Button(user_win, text="Cerrar sesión", command=lambda: cerrar_sesion(user_win)).pack(pady=10)


def abrir_interfaz_admin():
    admin_win = tk.Toplevel(root)
    admin_win.title("Panel de Administrador")
    admin_win.geometry("900x500")

    tk.Label(admin_win, text=f"Administrador: {usuario_actual}", font=("Arial", 12, "bold")).pack(pady=6)

    frame = tk.Frame(admin_win)
    frame.pack(pady=6)

    tk.Button(frame, text="Ver usuarios", width=15, command=lambda: ver_usuarios(admin_win)).grid(row=0, column=0, padx=5)
    tk.Button(frame, text="Ver roles", width=15, command=lambda: ver_roles(admin_win)).grid(row=0, column=1, padx=5)
    tk.Button(frame, text="Ver tokens JWT", width=15, command=lambda: ver_tokens(admin_win)).grid(row=0, column=2, padx=5)
    tk.Button(frame, text="Cambiar rol", width=15, command=lambda: abrir_cambio_rol(admin_win)).grid(row=0, column=3, padx=5)
    tk.Button(frame, text="Cerrar sesión", width=15, command=lambda: cerrar_sesion(admin_win)).grid(row=0, column=4, padx=5)

    cols = ("id", "username", "roles")
    tree = ttk.Treeview(admin_win, columns=cols, show="headings")
    for c in cols:
        tree.heading(c, text=c.capitalize())
    tree.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

    admin_win._tree = tree


def ver_usuarios(win):
    tree = win._tree
    tree.delete(*tree.get_children())
    resp = requests.get(f"{API_URL}/users", headers=obtener_headers())
    if resp.status_code == 200:
        for u in resp.json():
            roles = ", ".join([r if isinstance(r, str) else r.get("name") for r in u.get("roles", [])])
            tree.insert("", "end", values=(u.get("id"), u.get("username"), roles))
    else:
        messagebox.showerror("Error", resp.text)


def ver_roles(win):
    tree = win._tree
    tree.delete(*tree.get_children())
    resp = requests.get(f"{API_URL}/roles", headers=obtener_headers())
    if resp.status_code == 200:
        for r in resp.json():
            tree.insert("", "end", values=("", "", r))
    else:
        messagebox.showerror("Error", resp.text)


def ver_tokens(win):
    tree = win._tree
    tree.delete(*tree.get_children())
    resp = requests.get(f"{API_URL}/tokens", headers=obtener_headers())
    if resp.status_code == 200:
        for t in resp.json():
            if isinstance(t, dict):
                usuario = t.get("usuario") or t.get("sub", "N/A")
                token = t.get("token") or str(t)
            else:
                usuario, token = "", str(t)
            tree.insert("", "end", values=("", usuario, token[:124]))
    else:
        messagebox.showerror("Error", resp.text)


def abrir_cambio_rol(win):
    dlg = tk.Toplevel(win)
    dlg.title("Cambiar rol de usuario")
    dlg.geometry("300x150")

    tk.Label(dlg, text="Usuario:").pack()
    e_user = tk.Entry(dlg)
    e_user.pack()

    tk.Label(dlg, text="Nuevo rol (USER o ADMIN):").pack()
    e_role = tk.Entry(dlg)
    e_role.pack()

    def confirmar():
        usuario = e_user.get().strip()
        rol = e_role.get().strip().upper()
        if not usuario or not rol:
            messagebox.showwarning("Error", "Completa todos los campos")
            return
        resp = requests.post(f"{API_URL}/users/{usuario}/change-role", params={"new_role": rol}, headers=obtener_headers())
        if resp.status_code == 200:
            messagebox.showinfo("Éxito", f"Rol de {usuario} cambiado a {rol}")
            dlg.destroy()
            ver_usuarios(win)
        else:
            messagebox.showerror("Error", resp.text)

    tk.Button(dlg, text="Confirmar", command=confirmar).pack(pady=10)


# =======================
# LOGIN WINDOW
# =======================
def mostrar_login():
    login_win = tk.Toplevel(root)
    login_win.title("Inicio de sesión - API REST")
    login_win.geometry("350x230")

    tk.Label(login_win, text="Usuario:").pack(pady=5)
    entry_usuario = tk.Entry(login_win)
    entry_usuario.pack()

    tk.Label(login_win, text="Contraseña:").pack(pady=5)
    entry_contra = tk.Entry(login_win, show="*")
    entry_contra.pack()

    tk.Button(login_win, text="Iniciar sesión", command=lambda: iniciar_sesion(entry_usuario.get(), entry_contra.get(), login_win)).pack(pady=8)
    tk.Button(login_win, text="Registrar usuario", command=lambda: registrar_usuario(entry_usuario.get(), entry_contra.get(), login_win)).pack()

    # Centrar ventana y bloquear root mientras esté activa
    root.eval(f'tk::PlaceWindow {str(login_win)} center')
    login_win.grab_set()


# =======================
# MAIN
# =======================
if __name__ == "__main__":
    root = tk.Tk()
    root.withdraw()  # oculta la ventana raíz principal
    mostrar_login()
    root.mainloop()

