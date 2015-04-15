using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using System.Text;
using System.Threading.Tasks;

namespace Neo4j.AspNet.Identity
{
	static class Extensions
	{
		static bool IsValidNeoType(Type type)
		{
			if (type.IsPrimitive)
				return true;

			if (type == typeof(string))
				return true;

			if (type.HasElementType)
				return IsValidNeoType(type.GetElementType());
			
			return false;
		}

		public static T PrimitiveOnlyCopy<T>(this T source)
		{
			var clone = Activator.CreateInstance<T>();

			var fields = typeof(T).GetFields(BindingFlags.Public | BindingFlags.Instance);
			var props = typeof(T).GetProperties(BindingFlags.Public | BindingFlags.Instance);

			foreach(var field in fields.Where(f => IsValidNeoType(f.FieldType)))
			{
				var value = field.GetValue(source);
				field.SetValue(clone, value);
			}

			foreach (var prop in props.Where(p => IsValidNeoType(p.PropertyType)))
			{
				var value = prop.GetValue(source);
				prop.SetValue(clone, value);
			}

			return clone;
		}
	}
}