#ifndef _SYS_DISK_H
#define _SYS_DISK_H
/*
 * Five categories, from faster to slower:
 *
 * nonrot (SSD)      disk or mirror
 * nonrot (SSD)      raidz
 * mixed nonrot+rot  anything (raidz makes little sense)
 * rot (HDD)         disk or mirror
 * rot (HDD)         raidz
 */

#define	METASLAB_ROTOR_VDEV_TYPE_SSD		0x01
#define	METASLAB_ROTOR_VDEV_TYPE_SSD_RAIDZ	0x02
#define	METASLAB_ROTOR_VDEV_TYPE_MIXED		0x04
#define	METASLAB_ROTOR_VDEV_TYPE_HDD		0x08
#define	METASLAB_ROTOR_VDEV_TYPE_HDD_RAIDZ	0x10

#endif
