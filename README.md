# Scheduler X v2

1. Crear app "Native App" con permisos **Read and write** y callbacks `http://localhost:8721/callback` y `http://127.0.0.1:8721/callback`.
2. Agregar scopes: `users.read tweet.read tweet.write media.write offline.access`.
3. Ejecutar `prime_refresh.py` local con `X_CLIENT_ID` para obtener `refresh_token`.
4. Cargar secretos en GitHub, subir imágenes a `media/`, editar `calendar.csv` y ejecutar **Actions → Run workflow**.
