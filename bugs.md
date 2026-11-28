# Cosas que he notado
- Al seleccionar la interfaz panda y al ponerla al modo monitor, parece que tambien selecciona a mi interfaz principal como modo monitor. Que las selecciones sean unicamente a la que se agarre y los cambios unicamente se apliquen a esta
- En pleno escaneo, se traba la plataforma (parecen race conditions) y no permite hacer otra seleccion
	- Modo monitor -> escaneo -> No permite seleccionar otras redes -> Se buguea y no deja salir de la plataforma con q y menos con cntrl+c


# Que haras
- Lo comentado arriba
- Crearas capa de tests unitarios y e2e para garantizar funcionalidad completa en la plataforma
- Reducir drasticamente los bugs y hacerlo funcional
- Integrar CI y buenos PRs / commits para que proximas sesiones tuyas tengan mejor contexto
