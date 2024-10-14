import {
  CircleIcon,
  // WindmillIcon,
  // TypographyIcon,
  // ShadowIcon,
  // PaletteIcon,
  KeyIcon,
  // BugIcon,
  // DashboardIcon,
  // UserOffIcon,
  UsersGroupIcon,
  Home2Icon,
  PictureInPictureOnIcon,
  UserPlusIcon,
  BrandDeliverooIcon,
  BrandAppstoreIcon,
  DatabaseExportIcon,
  BrandOfficeIcon,
  // BrandChromeIcon,
  // HelpIcon
} from 'vue-tabler-icons';

export interface menu {
  header?: string;
  title?: string;
  icon?: object;
  to?: string;
  divider?: boolean;
  chip?: string;
  chipColor?: string;
  chipVariant?: string;
  chipIcon?: string;
  children?: menu[];
  disabled?: boolean;
  type?: string;
  subCaption?: string;
  forAdmin?: boolean;
}

const sidebarItem: menu[] = [
  // { header: 'Dashboard' }, 
  {
    title: 'Default',
    icon: Home2Icon,
    to: '/dashboard/default'
  },
  {
    title: "Thống kê",
    icon: DatabaseExportIcon,
    to: "/statistic"
  },
  {
    title: "Quản lý Kho",
    icon: BrandAppstoreIcon,
    to: "/storage"
  },
  {
    title: "Quản lý giao hàng",
    icon: BrandDeliverooIcon,
    to: "/delivery"
  },
  {
    title: "Quản lý dự án",
    icon: PictureInPictureOnIcon,
    to: "/projects"
  },
  {
    title: "Quản lý nhân viên",
    icon: UsersGroupIcon,
    to: "/users",
    forAdmin: true
  },
  {
    title: "Quản lý khách hàng",
    icon: UserPlusIcon,
    to: "/customers"
  },
  {
    title: "Quản lý phòng ban",
    icon: BrandOfficeIcon,
    to: "/offices"
  },
  // { divider: true },
  // { header: 'Pages' },
  // {
  //   title: 'Authentication',
  //   icon: KeyIcon,
  //   to: '/auth',
  //   children: [
  //     {
  //       title: 'Login',
  //       icon: CircleIcon,
  //       to: '/auth/login'
  //     },
  //     {
  //       title: 'Register',
  //       icon: CircleIcon,
  //       to: '/auth/register'
  //     }
  //   ]
  // },
  // {
  //   title: 'Error 404',
  //   icon: BugIcon,
  //   to: '/pages/error'
  // },
  // { divider: true },
  // { header: 'Utilities' },
  // {
  //   title: 'Typography',
  //   icon: TypographyIcon,
  //   to: '/utils/typography'
  // },
  // {
  //   title: 'Shadows',
  //   icon: ShadowIcon,
  //   to: '/utils/shadows'
  // },
  // {
  //   title: 'Colors',
  //   icon: PaletteIcon,
  //   to: '/utils/colors'
  // },

  // {
  //   title: 'Icons',
  //   icon: WindmillIcon,
  //   to: '/forms/radio',
  //   children: [
  //     {
  //       title: 'Tabler Icons',
  //       icon: CircleIcon,
  //       to: '/icons/tabler'
  //     },
  //     {
  //       title: 'Material Icons',
  //       icon: CircleIcon,
  //       to: '/icons/material'
  //     }
  //   ]
  // },
  // { divider: true },
  // {
  //   title: 'Sample Page',
  //   icon: BrandChromeIcon,
  //   to: '/starter'
  // },
  // {
  //   title: 'Documentation',
  //   icon: HelpIcon,
  //   to: 'https://codedthemes.gitbook.io/berry-vuetify/',
  //   type: 'external'
  // }
];

export default sidebarItem;
