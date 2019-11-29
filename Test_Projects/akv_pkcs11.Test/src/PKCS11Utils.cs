/*******************************************************************************
 *
 *                                   GRADIANT
 *
 *     Galician Research And Development center In AdvaNced Telecommunication
 *
 *
 * Copyright (c) 2019 by Gradiant. All rights reserved.
 * Licensed under the Mozilla Public License v2.0 (the "LICENSE").
 * https://github.com/Gradiant/BlackICE_Connect/LICENSE
 *******************************************************************************/

using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

/* DO NOT MODIFY this without tweaking compilation.sh */
using c_ulong = System.UInt32;
using c_long = System.Int32;
using c_uint = System.UInt32;
using c_int = System.Int32;

namespace akv_pkcs11.Test
{
    public class PKCS11Utils
    {
        /**
         * @brief Frees the attributes used in the template. It assumes that there's a CK_ATTRIBUTE[]
         * inside with <length> elements.
         *
         * @param template [in] IntPtr containing all attributes laid out in memory as an array.
         * @param arrayLength [in] number of attributes in the array stored in the template.
         */
        public static void FreeTemplateAttributesIntPtr(IntPtr template, c_int arrayLength)
        {
            if (template == IntPtr.Zero) return;

            c_int attributeSize = Marshal.SizeOf(typeof(CK_ATTRIBUTE));
            for (c_int i = 0; i < arrayLength; ++i)
            {
                CK_ATTRIBUTE attribute = (CK_ATTRIBUTE)Marshal.PtrToStructure(template + (attributeSize * i), typeof(CK_ATTRIBUTE));
                if (attribute.pValue != IntPtr.Zero)
                {
                    Marshal.FreeHGlobal(attribute.pValue);
                    attribute.pValue = IntPtr.Zero;
                }
            }
        }

        /**
         * @brief Copies the amount of bytes specified from one IntPtr to another.
         *
         * @param src [in] source IntPtr buffer from which to copy.
         * @param count [in] amount of bytes to copy.
         * @param dest [in, out] destination buffer in which to copy.
         * @param destOffset [in] offset to apply in the dest buffer (allows copying arrays).
         */
        public static void MemoryCopyToIntPtr(IntPtr src, c_int count, IntPtr dest, c_int destOffset)
        {
            Byte[] swapBuffer = new Byte[count];
            Marshal.Copy(src, swapBuffer, 0, count);
            Marshal.Copy(swapBuffer, 0, dest + destOffset, count);
        }

        public static c_int GetSizeOfTuple(Tuple<c_ulong, Byte[], c_ulong> tuple)
        {
            c_int tupleSize = 0;
            tupleSize += Marshal.SizeOf(tuple.Item1);
            tupleSize += Marshal.SizeOf(typeof(IntPtr));
            tupleSize += Marshal.SizeOf(tuple.Item3);
            return tupleSize;
        }

        public static c_int GetSizeOfTupleArray(Tuple<c_ulong, Byte[], c_ulong>[] tupleArray)
        {
            c_int arraySize = 0;
            for (c_int i = 0; i < tupleArray.Length; ++i)
            {
                arraySize += GetSizeOfTuple(tupleArray[i]);
            }
            return arraySize;
        }

        public static c_int GetTupleOffset(c_int index, Tuple<c_ulong, Byte[], c_ulong>[] tupleArray)
        {
            c_int offset = 0, i = 0;
            while (i < tupleArray.Length && i < index)
            {
                offset += GetSizeOfTuple(tupleArray[i]);
                ++i;
            }
            return offset;
        }

        public static void InsertAttributesIntPtr(IntPtr template, Tuple<c_ulong, Byte[], c_ulong>[] tupleArray)
        {
            c_int arraySize = tupleArray.Length;
            CK_ATTRIBUTE[] attributes = new CK_ATTRIBUTE[tupleArray.Length];

            for (c_int i = 0; i < arraySize; i++)
            {
                attributes[i].type = tupleArray[i].Item1;
                attributes[i].pValue = Marshal.AllocHGlobal(Convert.ToInt32(tupleArray[i].Item3));
                Marshal.Copy(tupleArray[i].Item2, 0, attributes[i].pValue, Convert.ToInt32(tupleArray[i].Item3));
                attributes[i].ulValueLen = tupleArray[i].Item3;

                c_int currentTupleSize = GetSizeOfTuple(tupleArray[i]);
                IntPtr currentAttribute = Marshal.AllocHGlobal(currentTupleSize);
                Marshal.StructureToPtr(attributes[i], currentAttribute, false);

                MemoryCopyToIntPtr(currentAttribute, currentTupleSize, template, GetTupleOffset(i, tupleArray));

                Marshal.FreeHGlobal(currentAttribute);
            }
        }

        /*
         * @brief Writes a given long value into the destination buffer.
         *
         * It will use WriteInt64/WriteInt32 depending on the platform (Linux/Windows, respectively).
         *
         * @param dest [in, out] destination buffer in which to write.
         * @param value [in] long int to write into the buffer.
         * @param offset [in] offset inside the buffer.
         */
        public static void WriteIntInBuffer(IntPtr dest, c_long value, c_int offset)
        {
#if (LINUX)
            Marshal.WriteInt64(dest + offset, value);
#else
            Marshal.WriteInt32(dest + offset, value);
#endif
        }

        /*
         * @brief Reads a long value from a given buffer, with the specified offset.
         *
         * It will use ReadInt64/ReadInt32 depending on the platform (Linux/Windows, respectively).
         *
         * @param src [in] buffer from which to read.
         * @param offset [in] offset inside the buffer.
         */
        public static c_long ReadLongFromBuffer(IntPtr src, c_int offset)
        {
#if (LINUX)
            return (c_long)Marshal.ReadInt64(src, offset);
#else
            return (c_long)Marshal.ReadInt32(src, offset);
#endif
        }

        public static string ByteArrayToString(Byte[] ba)
        {
            StringBuilder hex = new StringBuilder(ba.Length * 2);
            foreach (Byte b in ba)
                hex.AppendFormat("{0:x2}", b);
            return hex.ToString();
        }
    }
}
